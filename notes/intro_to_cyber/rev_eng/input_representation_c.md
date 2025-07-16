---
tags: ["Reverse Engineering", "Metadata"]
title: "Input Representation in C"
description: Input Representation in C
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to [input_representation_python.md](input_representation_python.md), but in C.

# Solution

## 1. check the c program

```c
void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
    uint64_t version;
    uint16_t width;
    uint16_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 1)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (cimg.header.width != 66)
    {
        puts("ERROR: Incorrect width!");
        exit(-1);
    }

    if (cimg.header.height != 17)
    {
        puts("ERROR: Incorrect height!");
        exit(-1);
    }

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    if (won) win();

}
```

Pixel constraints: `0x20 <= pixel.ascii <= 0x7E`

Header structure:

```c
struct cimg_header
{
    char magic_number[4];
    uint64_t version;
    uint16_t width;
    uint16_t height;
} __attribute__((packed));
```

## 2. create a proper cimg file based on (1)

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"cIMG"
    version = 1
    version = version.to_bytes(8, "little")
    width = b"\x42\x00"
    height = b"\x11\x00"

    data = bytes([33 for _ in range(62*23)])

    f.write(magic)
    f.write(version)
    f.write(width)
    f.write(height)
    f.write(data)
```

## 3. run cimg

```
hacker@reverse-engineering~input-restrictions-c:/challenge$ ./cimg  ~/flag.cimg
pwn.college{4yD6wrhVRBgujmF4fqiMGgHEn_g.0FNxUjNxwCM0YjMyEzW}
```
