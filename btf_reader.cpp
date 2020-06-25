// Copyright (C) 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <asm-generic/int-ll64.h>
#include <assert.h>
#include <fcntl.h>
#include <iostream>
#include <libelf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using std::cout;

void print_header_members(btf_header *header) {
    cout << "btf_header:\n";
    cout << "\tmagic " << header->magic << ", version " << header->version << ", flags " << header->flags << ", hdr_len " << header->hdr_len << "\n";
    cout << "\ttype_off " << header->type_off << ", type_len " << header->type_len << "\n";
    cout << "\tstr_off " << header->str_off << ", str_len " << header->str_len << "\n";
    return;
}

void print_string_section(__u32 str_len, char *str_start) {
    cout << "String section:\n";
    for (int i = 0; i < str_len; i++) {
        if (*(str_start + i) == '\0') {
            i++;
            cout << "\t" << (str_start + i) << "\n";
        }
    }
    return;
}

void read_members(int vlen, btf_member **member_list, char *after_type, int kflag) {
    for (int i = 0; i < vlen; i++) {
        member_list[i] = reinterpret_cast<btf_member *>(after_type + i * 32 * 3);
        if (kflag == 1) {
            cout << "\tname off " << member_list[i]->name_off << ", type " << member_list[i]->type << ", bitfield size " << BTF_MEMBER_BITFIELD_SIZE(member_list[i]->offset) << ", bit offset " << BTF_MEMBER_BIT_OFFSET(member_list[i]->offset) << "\n";
        } else {
            cout << "\tname off " << member_list[i]->name_off << ", type " << member_list[i]->type << ", offset " << member_list[i]->offset << "\n";
        }
    }
    return;
}

void read_enums(int vlen, btf_enum **kind_enum_list, char *after_type) {
    for (int i = 0; i < vlen; i++) {
        kind_enum_list[i] = reinterpret_cast<btf_enum *>(after_type + i * 32 * 2);
        cout << "\tname_off " << kind_enum_list[i]->name_off << ", val " << kind_enum_list[i]->val << "\n";
    }
    return;
}

void read_params(int vlen, btf_param **func_param_list, char *after_type) {
    for (int i = 0; i < vlen; i++) {
        func_param_list[i] = reinterpret_cast<btf_param *>(after_type + i * 32 * 2);
        cout << "\tname_off " << func_param_list[i]->name_off << ", type " << func_param_list[i]->type << "\n";
    }
    return;
}

void read_datasec(int vlen, btf_var_secinfo **secinfo_list, char *after_type) {
    for (int i = 0; i < vlen; i++) {
        secinfo_list[i] = reinterpret_cast<btf_var_secinfo *>(after_type + i * 32 * 3);
        cout << "\ttype " << secinfo_list[i]->type << ", offset " << secinfo_list[i]->offset << ", size " << secinfo_list[i]->size << "\n";
    }
    return;
}

int main() {
    const char *file_name = "test.btf";
    int fd = open(file_name, O_RDONLY);
    assert(fd >= 0);

    struct stat s;
    int status = fstat(fd, &s);
    assert(status >= 0);

    void *start = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(start != MAP_FAILED);

    int fclosed = close(fd);
    assert(fclosed == 0);

    btf_header *header = reinterpret_cast<btf_header *>(start);
    assert(header->magic == 60319);  // 0xEB9f
    print_header_members(header);

    btf_type *type_section = reinterpret_cast<btf_type *>((char *)start + header->hdr_len + header->type_off);
    __u32 kind = BTF_INFO_KIND(type_section->info);
    __u32 vlen = BTF_INFO_VLEN(type_section->info);
    __u32 kflag = BTF_INFO_KFLAG(type_section->info);

    cout << "\nbtf_type:\n\tname_off " << type_section->name_off << ", kind " << kind << ", vlen " << vlen << ", kflag " << kflag << "\n";

    __u32 *kind_int_val;
    btf_array *kind_arr;
    btf_var *kind_var;
    btf_enum *kind_enum_list[vlen];
    btf_member *member_list[vlen];
    btf_param *func_param_list[vlen];
    btf_var_secinfo *secinfo_list[vlen];
    char *after_type = (char *)start + header->hdr_len + header->type_off + 32 * 3;
    switch (kind) {
        case BTF_KIND_INT: {
            kind_int_val = reinterpret_cast<__u32 *>(after_type);
            cout << "BTF_KIND_INT:\n\tint encoding " << BTF_INT_ENCODING(*kind_int_val) << ", offset " << BTF_INT_OFFSET(*kind_int_val) << ", bits " << BTF_INT_BITS(*kind_int_val) << "\n";
            cout << "\tsize " << type_section->size << "\n";
            break;
        }
        case BTF_KIND_PTR: {
            cout << "BTF_KIND_PTR:\n\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_ARRAY: {
            kind_arr = reinterpret_cast<btf_array *>(after_type);
            cout << "BTF_KIND_ARRAY:\n\ttype " << kind_arr->type << ", index type " << kind_arr->index_type << ", num elems " << kind_arr->nelems << "\n";
            break;
        }
        case BTF_KIND_STRUCT: {
            cout << "BTF_KIND_STRUCT:\n";
            read_members(vlen, member_list, after_type, kflag);
            cout << "\tsize " << type_section->size << "\n";
            break;
        }
        case BTF_KIND_UNION: {
            cout << "BTF_KIND_UNION:\n";
            read_members(vlen, member_list, after_type, kflag);
            cout << "\tsize " << type_section->size << "\n";
            break;
        }
        case BTF_KIND_ENUM: {
            cout << "BTF_KIND_ENUM:\n";
            read_enums(vlen, kind_enum_list, after_type);
            cout << "\tsize " << type_section->size << "\n";
            break;
        }
        // case BTF_KIND_FWD: {
        //     break;
        // }
        case BTF_KIND_TYPEDEF: {
            cout << "BTF_KIND_TYPEDEF:\n\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_VOLATILE: {
            cout << "BTF_KIND_VOLATILE:\n\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_CONST: {
            cout << "BTF_KIND_CONST:\n\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_RESTRICT: {
            cout << "BTF_KIND_RESTRICT:\n\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_FUNC: {
            cout << "BTF_KIND_FUNC:\n\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_FUNC_PROTO: {
            cout << "BTF_KIND_FUNC_PROTO:\n";
            read_params(vlen, func_param_list, after_type);
            cout << "\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_VAR: {
            kind_var = reinterpret_cast<btf_var *>(after_type);
            cout << "\ttype " << type_section->type << "\n";
            break;
        }
        case BTF_KIND_DATASEC: {
            cout << "BTF_KIND_DATASEC:\n";
            read_datasec(vlen, secinfo_list, after_type);
            cout << "\tsize " << type_section->size << "\n";
            break;
        }
        default:
            assert(false);
    }

    char *str_start = (char *)start + header->hdr_len + header->str_off;
    print_string_section(header->str_len, str_start);

    int unmapped = munmap(header, s.st_size);
    assert(unmapped != -1);

    return 0;
}
