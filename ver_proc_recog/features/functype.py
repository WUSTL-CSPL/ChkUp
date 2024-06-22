"""This module is for adding more features in the near future."""

from functools import reduce

from utilities.sim_utils import mean

from . import Feature


class TypeFeature(Feature):
    @staticmethod
    def get(f):
        args = f["args"]
        abstract_args = f["abstract_args_type"]
        ret_type = f["abstract_ret_type"]
        arg_types = []
        for arg_type in abstract_args:
            arg_types.append(arg_type[2])

        # print(arg_types)
        # print(ret_type)

        features = {}
        features["data_num_args"] = len(arg_types)
        if arg_types:
            type_nums = list(map(lambda x: make_number(x), arg_types))
            features["data_sum_arg_type"] = sum(type_nums)
            features["data_avg_arg_type"] = mean(type_nums)
            features["data_mul_arg_type"] = reduce(lambda x, y: x * y, type_nums)
            features["data_sum_arg_type_seq"] = sum(
                map(lambda x: (x[0] + 1) * x[1], enumerate(type_nums))
            )
        features["data_ret_type"] = make_number(ret_type)
        return features


TYPE_MAP = {
    "func": 2,
    "void *": 2,
    "struct *": 2,
    "short *": 2,
    "int *": 2,
    "char *": 2,
    "enum *": 2,
    "float *": 2,
    "func *": 2,
    "union *": 2,
    "int": 3,
    "char": 5,
    "short": 7,
    "enum": 11,
    "float": 13,
    "struct": 17,
    "union": 17,
    "void": 19,
    "EVP_PKEY_CTX *": 2,
    "undefined": 23,
    "undefined4": 23,
    "undefined2": 23,
    "typedef size_t ulong": 29,
    "typedef __pid_t int": 3,
    "ulong": 29,
    "typedef ssize_t __ssize_t": 31,
    "sigset_t *": 2,
    "long": 29,
    "tms *": 2,
    "typedef clock_t __clock_t": 37,
    "typedef __useconds_t uint": 3,
    "char * *": 2, 
    "FILE *": 2,
    "typedef __gnuc_va_list void *": 2,
    "fd_set *": 2,
    "timeval *": 2,
    "typedef __off_t long": 29,
    "sockaddr *": 2,
    "socklen_t *": 2,
    "timespec *": 2,
    "double": 41, 
    "stat *": 2,
    "time_t *": 2,
    "typedef socklen_t __socklen_t": 43,
    "typedef in_addr_t uint32_t": 3,
    "typedef __sighandler_t __sighandler_t *": 2,
    "sigaction *": 2,
    "typedef __timezone_ptr_t timezone *": 2,
    "tm *": 2,
    "uint": 3
}


def make_number(t):
    return TYPE_MAP.get(t, 23)


def normalize_type(l):
    return list(map(make_number, l))
