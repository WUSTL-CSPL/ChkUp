import os
import logging
import coloredlogs
import yaml
import numpy as np
from multiprocessing import cpu_count
import warnings

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)

from utilities.sim_utils import load_func_data, do_multiprocess, get_base, get_func_data_fname, store_func_data, load_func_data_adv, store_func_data_adv, flatten

from ver_proc_recog.features import FeatureManager
from ver_proc_recog.features.functype import TypeFeature
from ver_proc_recog.ghidra_analysis_feature import ghidra_analysis_batch, ghidra_analysis

import configs.analysis_config as config


class FunctionMatcher:
    # it should take binary and function addresses for similarity matching
    # image_elf_list: list of (image, elfs)
    def preprocess_images(self, image_elf_list):
        logger.info("Loading elf files ...")

        # Merge elfs of succesfully extracted images
        elfs = []
        for image, image_elfs in image_elf_list:
            elfs.extend(image_elfs)

        logger.info("Done.")

        logger.info("Processing %d elfs ...", len(elfs))
        ghidra_analysis_batch(elfs)
        logger.info("Done.")

        # Second, extract features
        logger.info("Extracting features in %d elfs ...", len(elfs))
        do_multiprocess(
            self.extract_features_helper,
            elfs,
            chunk_size=1,
            threshold=1,
        )
        logger.info("Done.")
    
    
    def extract_features_helper(self, bin_path, force=False, depth=1):
        global feature_funcs

        # First check if cache exists
        func_data_fname = get_func_data_fname(bin_path, suffix="_features")
        if not force and os.path.exists(func_data_fname):
            return

        try:
            if 'unpacked_dataset' in bin_path:
                bin_path, func_data_list = load_func_data_adv(config.FEATURES_PATH, bin_path, suffix="")
            else:
                bin_path, func_data_list = load_func_data(bin_path, suffix="")

        except FileNotFoundError:
            print("No such file: ", bin_path)
            return

        # First, extract features
        fm = FeatureManager()
        func_data_map = {}
        for func_data in func_data_list:
            func_data["bin_path"] = bin_path
            if func_data["seg_name"] == "extern":
                continue
            try:
                features = {}
                for feature in fm.all_features:
                    # We do not have type feature. One may extend this with type recovery techniques.
                    if feature == TypeFeature:
                        continue
                    features.update(feature.get(func_data))
                func_data["feature"] = features
                func_data_map[func_data["name"]] = func_data
            except:
                import traceback

                traceback.print_exc()
                print("Error: ", bin_path)
                return

        # Second, merge features by depth-1
        for func_data in func_data_list:
            try:
                if func_data["seg_name"] == "extern":
                    continue

                features = func_data["feature"].copy()
                strings = func_data["strings"].copy()
                callers = func_data["callers"].copy()
                callees = func_data["callees"].copy()
                imported_callees = func_data["imported_callees"].copy()
                cfg_size = func_data["cfg_size"]

                # Handle functions exist only in current binary
                if func_data["callees"]:
                    for callee in func_data["callees"]:
                        callee_name = callee[0]
                        if callee_name not in func_data_map:
                            continue

                        callee_data = func_data_map[callee_name]
                        cfg_size += callee_data["cfg_size"]

                        for feature, val in callee_data["feature"].items():
                            if "_avg_" in feature:
                                continue
                            if feature in features:
                                features[feature] += val
                            else:
                                features[feature] = val

                        strings.extend(callee_data["strings"])
                        callers.extend(callee_data["callers"])
                        callees.extend(callee_data["callees"])
                        imported_callees.extend(callee_data["imported_callees"])

                    for feature, val in features.items():
                        if "_avg_" not in feature:
                            continue

                        num_feature = feature.replace("_avg_", "_num_")
                        sum_feature = feature.replace("_avg_", "_sum_")
                        assert num_feature in features or sum_feature in features
                        if num_feature in features:
                            features[feature] = features[num_feature] / float(cfg_size)
                        else:
                            features[feature] = features[sum_feature] / float(cfg_size)

                func_data["feature_inter"] = features
                func_data["strings_inter"] = strings
                func_data["callers_inter"] = callers
                func_data["callees_inter"] = callees
                func_data["imported_callees_inter"] = imported_callees
            except:
                import traceback

                traceback.print_exc()

        if 'unpacked_dataset' in bin_path:
            store_func_data_adv(config.FEATURES_PATH, bin_path, func_data_list, suffix="_features")
        else:
            store_func_data(bin_path, func_data_list, suffix="_features")

    
    def match_funcs(self, image_elf_list, outdir, config_fname):
        if not os.path.exists(config_fname):
            logger.error("No such config file: %s", config_fname)
            return

        logger.info("config file name: %s", config_fname)
        with open(config_fname, "r") as f:
            config = yaml.safe_load(f)

        features = sorted(config["features"])
        num_features = len(features)
        logger.info("%d features", num_features)
        feature_indices = self.load_trained_features_all(features)

        target_funcs = {}
        target_strings = {}
        target_bins = set()
        for bin_path, funcs in config["target_funcs"].items():
            # parse addresses of funcs 
            funcs = [item.split(":")[0] for item in funcs]
            
            assert os.path.exists(bin_path), "No such file name: %s" % bin_path
            
            ghidra_analysis(bin_path)
            self.extract_features_helper(bin_path)
            bin_path, func_data_list = load_func_data(bin_path, suffix="_features")
            target_bins.add(bin_path)
            target_data_list = list(
                filter(
                    lambda x: x["startEA"] in funcs or x["name"] in funcs, func_data_list
                )
            )

            image_base = get_base(os.path.dirname(bin_path))
            bin_base = get_base(bin_path)
            for func_data in target_data_list:
                func_key = (
                    image_base,
                    bin_base,
                    func_data["startEA"],
                    func_data["name"],
                    func_data["arch"],
                )
                if func_key not in target_funcs:
                    target_funcs[func_key] = [
                        np.zeros(num_features, dtype=np.float64),  # depth-0
                        np.zeros(num_features, dtype=np.float64),  # depth-1
                    ]
                # String-related features
                # depth-0 feature
                for feature_idx, feature in enumerate(features):
                    if feature not in func_data["feature"]:
                        continue
                    val = func_data["feature"][feature]
                    target_funcs[func_key][0][feature_idx] = val

                if "feature_inter" not in func_data:
                    continue
                
                # depth-1 feature
                for feature_idx, feature in enumerate(features):
                    if feature not in func_data["feature_inter"]:
                        continue
                    val = func_data["feature_inter"][feature]
                    target_funcs[func_key][1][feature_idx] = val

        target_keys = sorted(target_funcs.keys())
        logger.info(
            "Loaded %d target functions in %d binaries.", len(target_keys), len(target_bins)
        )

        logger.info("Loading elf files ...")
        # Merge elfs of succesfully extracted images
        elfs = []
        images = set()
        for image, image_elfs in image_elf_list:
            images.add(image)

            for elf in image_elfs:
                elfs.append((image, elf))

        # First, process each binaries in parallel. The matching results will be
        # stored at files having suffix "_results"
        logger.info("Matching target functions ...")
        result_suffix = config["result_suffix"]
        do_multiprocess(
            self.calc_metric_helper,
            elfs,
            chunk_size=1,
            threshold=1,
            initializer=self._init_calc,
            initargs=(
                target_funcs,
                features,
                feature_indices,
                target_strings,
                result_suffix,
                outdir,
            ),
        )
        logger.info("Done.")

        # Next, merge the matching results for each image.
        logger.info("Start collecting the results ...")
        do_multiprocess(
            self.merge_results_helper,
            image_elf_list,
            pool_size=cpu_count() // 2,
            chunk_size=1,
            threshold=1,
            initializer=self._init_merge,
            initargs=(target_keys, outdir, config_fname, result_suffix),
        )
        logger.info("Done.")


    def jaccard_similarity(self, a, b):
        if not a:
            return 1
        if not b:
            return 0
        s1 = set(a)
        s2 = set(b)
        return float(len(s1.intersection(s2))) / len(s1.union(s2))


    def string_similarity(self, a, b):
        if not a:
            return 1
        if not b:
            return 0
        a_words = flatten(map(lambda x: x.split(), a))
        a_words = list(filter(lambda x: len(x) > 4, a_words))
        b_words = flatten(map(lambda x: x.split(), b))
        b_words = list(filter(lambda x: len(x) > 4, b_words))
        return self.jaccard_similarity(a_words, b_words)


    def calc_metric_helper(self, arg, force=False):
        global g_target_funcs, g_features, g_feature_indices
        global g_target_strings, g_result_suffix, g_outdir
        image_path, bin_path = arg
        bin_base = bin_path.replace("{}/{}".format(g_outdir, config.FW_NAME), "")

        # check if cache exists
        func_data_fname = get_func_data_fname(bin_path, suffix=g_result_suffix)
        if not force and os.path.exists(func_data_fname):
            return

        # Feature loading
        try:
            if 'unpacked_dataset' in bin_path:
                _, func_data_list = load_func_data_adv(config.FEATURES_PATH, bin_path, suffix="_features")
            else:
                _, func_data_list = load_func_data(bin_path, suffix="_features")
        except FileNotFoundError:
            print("No such file: ", image_path, bin_path)
            return (image_path, [])

        num_features = len(g_features)
        func_features = {}
        func_strings = {}
        for func_data in func_data_list:
            if not func_data or "feature" not in func_data:
                continue

            func_key = (
                config.FW_NAME,
                bin_base,
                func_data["startEA"],
                func_data["name"],
                func_data["arch"],
            )
            if func_key not in func_features:
                func_features[func_key] = [
                    np.zeros(num_features, dtype=np.float64),  # depth-0
                    np.zeros(num_features, dtype=np.float64),  # depth-1
                ]

            # String-related features            
            # depth-0 feature
            for feature_idx, feature in enumerate(g_features):
                if feature not in func_data["feature"]:
                    continue
                val = func_data["feature"][feature]
                func_features[func_key][0][feature_idx] = val

            if "feature_inter" not in func_data:
                continue

            # depth-1 feature
            for feature_idx, feature in enumerate(g_features):
                if feature not in func_data["feature_inter"]:
                    continue
                val = func_data["feature_inter"][feature]
                func_features[func_key][1][feature_idx] = val

        # Calculating
        results = {}
        for target_key, target_func in sorted(g_target_funcs.items()):
            target_results = []
            target_arch = target_key[-1]
            for func_key, func in sorted(func_features.items()):
                arch = func_key[-1]
                archs = [target_arch.split("_")[0], arch.split("_")[0]]
                archs = "_".join(archs)
                feature_indices = g_feature_indices[archs.lower()]

                func_results = [func_key]
                for depth in range(2):
                    rdiff = self.relative_difference(target_func[depth], func[depth])
                    rdist = self.relative_distance(rdiff, feature_indices)
                    score = [rdist] 
                    func_results.append(score)
                target_results.append(func_results)
            results[target_key] = target_results

        if 'unpacked_dataset' in bin_path:
            store_func_data_adv(config.FEATURES_PATH, bin_path, results, suffix=g_result_suffix)
        else:
            store_func_data(bin_path, results, suffix=g_result_suffix)


    def _init_calc(self, 
        target_funcs, features, feature_indices, target_strings, result_suffix, outdir
    ):
        global g_target_funcs, g_features, g_feature_indices
        global g_target_strings, g_result_suffix, g_outdir
        g_target_funcs = target_funcs
        g_features = features
        g_feature_indices = feature_indices
        g_target_strings = target_strings
        g_result_suffix = result_suffix
        g_outdir = outdir


    def load_trained_features_all(self, features):
        feature_indices = {}

        archs = ["arm", "mips", "x86", "mipseb"]
        arch_pairs = ["%s_%s" % (a, b) for a in archs for b in archs]

        for arch in arch_pairs:
            indices = []
            for feature in features:
                indices.append(features.index(feature))
                feature_indices[arch] = sorted(indices)
        return feature_indices
    
    
    def get_string_features(self, func_data):
        features = [
            self.get_second_elem(func_data["strings"]),
            self.filter_unknown(self.get_first_elem(func_data["callers"])),
            self.filter_unknown(self.get_first_elem(func_data["callees"])),
            self.filter_unknown(self.get_first_elem(func_data["imported_callees"])),
            self.filter_unknown([func_data["name"]]),
        ]

        features_inter = [
            self.get_second_elem(func_data["strings_inter"]),
            self.filter_unknown(self.get_first_elem(func_data["callers_inter"])),
            self.filter_unknown(self.get_first_elem(func_data["callees_inter"])),
            self.filter_unknown(self.get_first_elem(func_data["imported_callees_inter"])),
            self.filter_unknown([func_data["name"]]),
        ]

        return features, features_inter

    def relative_difference(self, a, b):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=RuntimeWarning)
            max_val = np.maximum(np.absolute(a), np.absolute(b))
            d = np.absolute(a - b) / max_val
            d[np.isnan(d)] = 0  # 0 / 0 = nan -> 0
            d[np.isinf(d)] = 1  # x / 0 = inf -> 1 (when x != 0)
            return d


    def relative_distance(self, X, feature_indices):
        return 1 - (np.sum(X[feature_indices])) / len(feature_indices)


    def merge_results_helper(self, arg):
        global g_target_keys, g_outdir, g_config_fname, g_result_suffix
        image, elfs = arg
        target_keys = g_target_keys
        outdir = g_outdir
        config_fname = g_config_fname.split("/")[-1].split(".")[0]


        image_scores = {}
        for target_key in target_keys:
            image_scores[target_key] = []

        for elf in elfs:
            try:
                _, results = load_func_data_adv(config.FEATURES_PATH, elf, suffix=g_result_suffix)
            except FileNotFoundError:
                continue
            except EOFError:
                print("Ran out of input: ", image, elf)
                continue

            for target_key, scores in results.items():
                # The result may have additional data.
                if target_key not in image_scores:
                    continue
                image_scores[target_key].extend(scores)

        for target_key in sorted(
            target_keys, key=lambda x: get_base(os.path.dirname(x[1]))
        ):
            target_image_idx = target_key[0]
            bin_name = get_base(target_key[1])
            func_addr = target_key[2]#)
            func_name = target_key[3]
            bin_arch = target_key[4]

            dir_name = "-".join(
                ["scores", target_image_idx, bin_name, func_addr, func_name, bin_arch]
            )
            dir_name = os.path.join(outdir, config_fname, dir_name)
            os.makedirs(dir_name, exist_ok=True)

            score_fname = os.path.join(dir_name, "scores{}.txt".format(config.FW_NAME))

            scores = sorted(image_scores[target_key], key=lambda x: x[1][0], reverse=True)
            out_str = ""
            func_keys = self.get_first_elem(scores)
            
            lines = []
            check_line = None
            for func_idx, func_key in enumerate(func_keys):
                func_scores = scores[func_idx][1:]
                func_key = list(func_key)
                func_key[0] = get_base(func_key[0])
                name = func_key[3]
                
                base_line = ",".join(map(str, func_key))

                for rdist in func_scores: 
                    line = base_line  
                    line += ":::{:.4f}".format(rdist[0])
                    if name == func_name:
                        check_line = line
                    else:
                        lines.append((rdist, line))
                
            lines.sort(key=lambda x: x[0], reverse=True)
            sorted_lines = [line for _, line in lines]
            if check_line:
                sorted_lines.insert(0, check_line)
            out_str = "\n".join(sorted_lines)
            with open(score_fname, "w") as f:
                f.write(out_str)
     

    def filter_unknown(self, l):
        return list(filter(lambda x: not str(x).startswith("sub_"), l)) 


    def get_first_elem(self, l):
        return list(map(lambda x: x[0], l))


    def get_second_elem(self, l):
        return list(map(lambda x: x[1], l))


    def _init_merge(self, target_keys, outdir, config_fname, result_suffix):
        global g_target_keys, g_outdir, g_config_fname, g_result_suffix
        g_target_keys = target_keys
        g_outdir = outdir
        g_config_fname = config_fname
        g_result_suffix = result_suffix
    
    ############### start of next script ################
    # image: firmware image path
    def check(self, image, outdir, config_fname):
        if not os.path.exists(config_fname):
            logger.error("No such config file: %s", config_fname)
            return

        logger.info("config file name: %s", config_fname)
        with open(config_fname, "r") as f:
            config = yaml.safe_load(f)

        # Loading target functions
        result_suffix = config["result_suffix"]
        target_keys = []
        target_bins = set()
        for bin_path, funcs in config["target_funcs"].items():
            
            funcs = [item.split(":")[0] for item in funcs]
            assert os.path.exists(bin_path), "No such file name: %s" % bin_path

            bin_path, func_data_list = load_func_data(bin_path, suffix="_features")
            target_bins.add(bin_path)

            # image, bin, addr, name, arch
            target_data_list = list(filter(lambda x: x["startEA"] in funcs, func_data_list))

            image_base = get_base(os.path.dirname(bin_path))
            bin_base = get_base(bin_path)
            for func_data in target_data_list:
                func_key = (
                    image_base,
                    bin_base,
                    func_data["startEA"],
                    func_data["name"],
                    func_data["arch"],
                )
                target_keys.append(func_key)
                target_func_name = func_data["name"]

        logger.info(
            "Loaded %d target functions in %d binaries.", len(target_keys), len(target_bins)
        )

        # Now check each score files
        logger.info("Start merging data ...")
        print((outdir, config_fname, target_keys))
        results = do_multiprocess(
            self.check_helper,
            [image],
            chunk_size=1,
            threshold=1,
            initializer=self._init_check,
            initargs=(outdir, config_fname, target_keys),
        )

        logger.info("Done.")
    
    
    def check_helper(self, image, force=False):
        global g_outdir, g_config_fname, g_target_keys
        
        outdir = g_outdir
        config_fname = g_config_fname.split("/")[-1].split(".")[0]
        target_keys = g_target_keys

        total_dir_name = os.path.join(outdir, config_fname, "scores-total")
        if not os.path.exists(os.path.join(outdir, config_fname)):
            os.makedirs(os.path.join(outdir, config_fname))
        os.makedirs(total_dir_name, exist_ok=True)
        total_score_fname = os.path.join(total_dir_name, "scores{}.txt".format(config.FW_NAME))

        if not force and os.path.exists(total_score_fname):
            with open(total_score_fname, "r") as f:
                lines = f.read().splitlines()

            for target_idx, target_key in enumerate(
                sorted(target_keys, key=lambda x: x[0])
            ):
                target_image_idx = target_key[0]
                target_bin_name = target_key[1]
                target_func_addr = target_key[2]
                target_func_name = target_key[3]
                target_bin_arch = target_key[4]
                break
            lines.sort(key=lambda x: self.scoring(x), reverse=True)

        else:
            results = {}
            for target_idx, target_key in enumerate(
                sorted(target_keys, key=lambda x: x[0])
            ):
                target_image_idx = target_key[0]
                target_bin_name = target_key[1]
                target_func_addr = target_key[2]
                target_func_name = target_key[3]
                target_bin_arch = target_key[4]

                dir_name = "-".join(
                    [
                        "scores",
                        target_image_idx,
                        target_bin_name,
                        target_func_addr,
                        target_func_name,
                        target_bin_arch,
                    ]
                )
                dir_name = os.path.join(outdir, config_fname, dir_name)

                score_fname = os.path.join(dir_name, "scores{}.txt".format(config.FW_NAME))
                with open(score_fname, "r") as f:
                    lines = f.read()

                lines = lines.splitlines()
                for idx, line in enumerate(lines):
                    scores = line.split(":::")
                    scores = list(map(lambda x: x.split(","), scores))
                    image_path, bin_path, func_addr, func_name, arch = scores[0]
                    bin_name = get_base(bin_path)

                    func_key = (bin_path, func_addr, func_name)
                    if func_key not in results:
                        results[func_key] = []

                    float_scores = []
                    for score in scores[1:]:
                        float_scores.append(list(map(float, score)))
                    results[func_key].append(float_scores)

            out_str = ""
            for func_key in results.keys():
                total_score = np.mean(results[func_key], axis=0)
                out_str += "{},".format(config.FW_NAME)
                out_str += ",".join(func_key)
                out_str += ",all"
                for score in total_score:
                    out_str += ":::{:.4f}".format(score[0])
                    for val in score[1:]:
                        out_str += ",{:.4f}".format(val)
                out_str += "\n"
            lines = out_str.splitlines()
            lines.sort(key=lambda x: self.scoring(x), reverse=True)
            with open(total_score_fname, "w") as f:
                for line in lines:
                    f.write(line + "\n")

        top_k = -1
        top_line = None
        top_score = 0
        prev_idx = 0
        prev_score = -1
        score_results = []
        for idx, line in enumerate(lines):
            final_score = self.scoring(line)
            score_results.append(final_score)
            if final_score == prev_score:
                idx = prev_idx
            else:
                prev_idx = idx
                prev_score = final_score

            if target_func_name in line:
                top_k = idx + 1
                top_line = line
                top_score = final_score
                break

        return config.FW_NAME, top_k, top_line, top_score
    

    def _init_check(self, outdir, config_fname, target_keys):
        global g_outdir, g_config_fname, g_target_keys
        g_outdir = outdir
        g_config_fname = config_fname
        g_target_keys = target_keys
        

    def scoring(self, x, alpha=1.0):

        scores = x.split(":::")
        scores = list(map(lambda x: x.split(","), scores))
        image_path, bin_path, func_addr, func_name, arch = scores[0]
        final_score = 0
        for depth, score in enumerate(scores[1:]):
            score = list(map(float, score))
            # print(score)
            rdist = score[0]
            str_score = score[1]
            caller_score = score[2]
            callee_score = score[3]
            imported_callee_score = score[4]
            func_name = score[5]

            if depth == 0:
                final_score += rdist * 1.0
                break

        # return the relative distance between functions
        return final_score
