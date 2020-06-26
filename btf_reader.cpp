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
#include <libelf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <vector>

using std::cout;
using std::vector;

struct btf_file {
    const char *file_name;
    int fd;
    size_t size;
    void *start;
} bf;

struct btf_structures {
    btf_header *header;
    btf_type *type_section;
    char *after_type_section;
    char *str_start;

    __u32 *kind_int_val;
    btf_array *kind_arr;
    btf_var *kind_var;
    vector<btf_enum *> kind_enum_list;
    vector<btf_member *> member_list;
    vector<btf_param *> func_param_list;
    vector<btf_var_secinfo *> secinfo_list;
} structures;

char *open_BTF() {
    bf.file_name = "test.btf";
    bf.fd = open(bf.file_name, O_RDONLY);
    assert(bf.fd >= 0);

    struct stat s;
    int fstat_status = fstat(bf.fd, &s);
    assert(fstat_status >= 0);
    bf.size = s.st_size;

    bf.start = mmap(0, bf.size, PROT_READ, MAP_PRIVATE, bf.fd, 0);
    assert(bf.start != MAP_FAILED);

    int fclosed = close(bf.fd);
    assert(fclosed == 0);

    return reinterpret_cast<char *>(bf.start);
}

void print_header_members(btf_header *header) {
    cout << "btf_header:\n";
    cout << "\tmagic " << header->magic << ", version " << header->version << ", flags " << header->flags << ", hdr_len " << header->hdr_len << "\n";
    cout << "\ttype_off " << header->type_off << ", type_len " << header->type_len << "\n";
    cout << "\tstr_off " << header->str_off << ", str_len " << header->str_len << "\n";
    return;
}

void read_members(int vlen, int kflag) {
    for (int i = 0; i < vlen; i++) {
        structures.member_list.push_back(reinterpret_cast<btf_member *>(structures.after_type_section + i * 32 * 3));
        if (kflag == 1) {
            cout << "\tname off " << structures.member_list.back()->name_off << ", type " << structures.member_list.back()->type << ", bitfield size " << BTF_MEMBER_BITFIELD_SIZE(structures.member_list.back()->offset) << ", bit offset " << BTF_MEMBER_BIT_OFFSET(structures.member_list.back()->offset) << "\n";
        } else {
            cout << "\tname off " << structures.member_list.back()->name_off << ", type " << structures.member_list.back()->type << ", offset " << structures.member_list.back()->offset << "\n";
        }
    }
    return;
}

void read_enums(int vlen) {
    for (int i = 0; i < vlen; i++) {
        structures.kind_enum_list.push_back(reinterpret_cast<btf_enum *>(structures.after_type_section + i * 32 * 2));
        cout << "\tname_off " << structures.kind_enum_list.back()->name_off << ", val " << structures.kind_enum_list.back()->val << "\n";
    }
    return;
}

void read_params(int vlen) {
    for (int i = 0; i < vlen; i++) {
        structures.func_param_list.push_back(reinterpret_cast<btf_param *>(structures.after_type_section + i * 32 * 2));
        cout << "\tname_off " << structures.func_param_list.back()->name_off << ", type " << structures.func_param_list.back()->type << "\n";
    }
    return;
}

void read_datasec(int vlen) {
    for (int i = 0; i < vlen; i++) {
        structures.secinfo_list.push_back(reinterpret_cast<btf_var_secinfo *>(structures.after_type_section + i * 32 * 3));
        cout << "\ttype " << structures.secinfo_list.back()->type << ", offset " << structures.secinfo_list.back()->offset << ", size " << structures.secinfo_list.back()->size << "\n";
    }
    return;
}

void analyse_type_section() {
    __u32 kind = BTF_INFO_KIND(structures.type_section->info);
    __u32 vlen = BTF_INFO_VLEN(structures.type_section->info);
    __u32 kflag = BTF_INFO_KFLAG(structures.type_section->info);

    cout << "\nbtf_type:\n\tname_off " << structures.type_section->name_off << ", kind " << kind << ", vlen " << vlen << ", kflag " << kflag << "\n";

    switch (kind) {
        case BTF_KIND_INT: {
            structures.kind_int_val = reinterpret_cast<__u32 *>(structures.after_type_section);
            cout << "BTF_KIND_INT:\n\tint encoding " << BTF_INT_ENCODING(*structures.kind_int_val) << ", offset " << BTF_INT_OFFSET(*structures.kind_int_val) << ", bits " << BTF_INT_BITS(*structures.kind_int_val) << "\n";
            cout << "\tsize " << structures.type_section->size << "\n";
            break;
        }
        case BTF_KIND_PTR: {
            cout << "BTF_KIND_PTR:\n\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_ARRAY: {
            structures.kind_arr = reinterpret_cast<btf_array *>(structures.after_type_section);
            cout << "BTF_KIND_ARRAY:\n\ttype " << structures.kind_arr->type << ", index type " << structures.kind_arr->index_type << ", num elems " << structures.kind_arr->nelems << "\n";
            break;
        }
        case BTF_KIND_STRUCT: {
            cout << "BTF_KIND_STRUCT:\n";
            read_members(vlen, kflag);
            cout << "\tsize " << structures.type_section->size << "\n";
            break;
        }
        case BTF_KIND_UNION: {
            cout << "BTF_KIND_UNION:\n";
            read_members(vlen, kflag);
            cout << "\tsize " << structures.type_section->size << "\n";
            break;
        }
        case BTF_KIND_ENUM: {
            cout << "BTF_KIND_ENUM:\n";
            read_enums(vlen);
            cout << "\tsize " << structures.type_section->size << "\n";
            break;
        }
        // case BTF_KIND_FWD: {
        //     break;
        // }
        case BTF_KIND_TYPEDEF: {
            cout << "BTF_KIND_TYPEDEF:\n\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_VOLATILE: {
            cout << "BTF_KIND_VOLATILE:\n\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_CONST: {
            cout << "BTF_KIND_CONST:\n\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_RESTRICT: {
            cout << "BTF_KIND_RESTRICT:\n\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_FUNC: {
            cout << "BTF_KIND_FUNC:\n\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_FUNC_PROTO: {
            cout << "BTF_KIND_FUNC_PROTO:\n";
            read_params(vlen);
            cout << "\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_VAR: {
            structures.kind_var = reinterpret_cast<btf_var *>(structures.after_type_section);
            cout << "\ttype " << structures.type_section->type << "\n";
            break;
        }
        case BTF_KIND_DATASEC: {
            cout << "BTF_KIND_DATASEC:\n";
            read_datasec(vlen);
            cout << "\tsize " << structures.type_section->size << "\n";
            break;
        }
        default:
            assert(false);
    }

    return;
}

void print_string_section() {
    cout << "String section:\n";
    for (int i = 0; i < structures.header->str_len; i++) {
        if (*(structures.str_start + i) == '\0') {
            i++;
            cout << "\t" << (structures.str_start + i) << "\n";
        }
    }
    return;
}

void close_and_unmap() {
    int unmapped = munmap(bf.start, bf.size);
    assert(unmapped != -1);
}

int main() {
    char *start = open_BTF();

    structures.header = reinterpret_cast<btf_header *>(start);
    assert(structures.header->magic == 60319);  // 0xEB9F
    print_header_members(structures.header);

    structures.type_section = reinterpret_cast<btf_type *>(start + structures.header->hdr_len + structures.header->type_off);
    structures.after_type_section = start + structures.header->hdr_len + structures.header->type_off + 32 * 3;
    analyse_type_section();

    structures.str_start = start + structures.header->hdr_len + structures.header->str_off;
    print_string_section();

    close_and_unmap();

    return 0;
}
