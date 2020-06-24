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

void print_header_members(struct btf_header *header) {
    printf("btf_header:\n");
    printf("\tmagic %x, version %u, flags %u, hdr_len %u\n", (*header).magic, (*header).version, (*header).flags, (*header).hdr_len);
    printf("\ttype_off %u, type_len %u \n", (*header).type_off, (*header).type_len);
    printf("\tstr_off %u, str_len %u \n", (*header).str_off, (*header).str_len);
    return;
}

void print_string_section(__u32 str_len, char *str_start) {
    printf("String section:\n");
    for (int i = 0; i < str_len; i++) {
        char *curr = str_start + i;
        if (*(str_start + i) == '\0') {
            i++;
            printf("\t%s\n", str_start + i);
        }
    }
    return;
}

void read_members(int vlen, btf_member **member_list, char *after_type, int kflag) {
    for (int i = 0; i < vlen; i++) {
        member_list[i] = reinterpret_cast<btf_member *>(after_type + i * 32 * 3);
        if (kflag == 1) {
            printf("\tname off %u, type %u, offset %u\n", (*member_list[i]).name_off, (*member_list[i]).type, BTF_MEMBER_BITFIELD_SIZE((*member_list[i]).offset), BTF_MEMBER_BIT_OFFSET((*member_list[i]).offset));
        } else {
            printf("\tname off %u, type %u, offset %u\n", (*member_list[i]).name_off, (*member_list[i]).type, (*member_list[i]).offset);
        }
    }
    return;
}

void read_enums(int vlen, struct btf_enum **kind_enum_list, char *after_type) {
    for (int i = 0; i < vlen; i++) {
        kind_enum_list[i] = reinterpret_cast<struct btf_enum *>(after_type + i * 32 * 2);
        printf("\tname_off %u, val %d\n", (*kind_enum_list[i]).name_off, (*kind_enum_list[i]).val);
    }
    return;
}

void read_params(int vlen, struct btf_param **func_param_list, char *after_type) {
    for (int i = 0; i < vlen; i++) {
        func_param_list[i] = reinterpret_cast<struct btf_param *>(after_type + i * 32 * 2);
        printf("\tname_off %u, type %u\n", (*func_param_list[i]).name_off, (*func_param_list[i]).type);
    }
    return;
}

void read_datasec(int vlen, struct btf_var_secinfo **secinfo_list, char *after_type) {
    for (int i = 0; i < vlen; i++) {
        secinfo_list[i] = reinterpret_cast<struct btf_var_secinfo *>(after_type + i * 32 * 3);
        printf("\ttype %u, offset %u, size %u\n", (*secinfo_list[i]).type, (*secinfo_list[i]).offset, (*secinfo_list[i]).size);
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

    struct btf_header *header = reinterpret_cast<struct btf_header *>(start);
    assert((*header).magic == 60319); // 0xEB9f
    print_header_members(header);

    struct btf_type *type = reinterpret_cast<struct btf_type *>((char *)start + (*header).hdr_len + (*header).type_off);
    __u32 kind = BTF_INFO_KIND((*type).info);
    __u32 vlen = BTF_INFO_VLEN((*type).info);
    __u32 kflag = BTF_INFO_KFLAG((*type).info);

    printf("\nbtf_type:\n\tname_off %u, kind %u, vlen %u, kflag %u\n", (*type).name_off, kind, vlen, kflag);

    __u32 *kind_int_val;
    struct btf_array *kind_arr;
    struct btf_var *kind_var;
    struct btf_enum *kind_enum_list[vlen];
    struct btf_member *member_list[vlen];
    struct btf_param *func_param_list[vlen];
    struct btf_var_secinfo *secinfo_list[vlen];
    char *after_type = (char *)start + (*header).hdr_len + (*header).type_off + 32 * 3;
    switch (kind) {
        case BTF_KIND_INT: {
            kind_int_val = reinterpret_cast<__u32 *>(after_type);
            printf("BTF_KIND_INT:\n\tint encoding %u, offset %u, bits%u\n", BTF_INT_ENCODING(*kind_int_val), BTF_INT_OFFSET(*kind_int_val), BTF_INT_BITS(*kind_int_val));
            printf("\tsize %u\n", (*type).size);
            break;
        }
        case BTF_KIND_PTR: {
            printf("BTF_KIND_PTR:\n\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_ARRAY: {
            kind_arr = reinterpret_cast<btf_array *>(after_type);
            printf("BTF_KIND_ARRAY:\n\ttype %u, index type %u, num elems %u\n", (*kind_arr).type, (*kind_arr).index_type, (*kind_arr).nelems);
            break;
        }
        case BTF_KIND_STRUCT: {
            printf("BTF_KIND_STRUCT:\n");
            read_members(vlen, member_list, after_type, kflag);
            printf("\tsize %u\n", (*type).size);
            break;
        }
        case BTF_KIND_UNION: {
            printf("BTF_KIND_UNION:\n");
            read_members(vlen, member_list, after_type, kflag);
            printf("\tsize %u\n", (*type).size);
            break;
        }
        case BTF_KIND_ENUM: {
            printf("BTF_KIND_ENUM:\n");
            read_enums(vlen, kind_enum_list, after_type);
            printf("\tsize %u\n", (*type).size);
            break;
        }
        // case BTF_KIND_FWD: {
        //     break;
        // }
        case BTF_KIND_TYPEDEF: {
            printf("BTF_KIND_TYPEDEF:\n\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_VOLATILE: {
            printf("BTF_KIND_VOLATILE:\n\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_CONST: {
            printf("BTF_KIND_CONST:\n\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_RESTRICT: {
            printf("BTF_KIND_RESTRICT:\n\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_FUNC: {
            printf("BTF_KIND_FUNC:\n\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_FUNC_PROTO: {
            printf("BTF_KIND_FUNC_PROTO:\n");
            read_params(vlen, func_param_list, after_type);
            printf("\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_VAR: {
            kind_var = reinterpret_cast<btf_var *>(after_type);
            printf("\ttype %u\n", (*type).type);
            break;
        }
        case BTF_KIND_DATASEC: {
            printf("BTF_KIND_DATASEC:\n");
            read_datasec(vlen, secinfo_list, after_type);
            printf("\tsize %u\n", (*type).size);
            break;
        }
        default:
            assert(false);
    }

    char *str_start = (char *)start + (*header).hdr_len + (*header).str_off;
    print_string_section((*header).str_len, str_start);

    int unmapped = munmap(header, s.st_size);
    assert(unmapped != -1);

    return 0;
}
