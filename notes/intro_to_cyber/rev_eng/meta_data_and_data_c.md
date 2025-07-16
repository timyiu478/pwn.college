---
tags: ["Reverse Engineering", "Metadata"]
title: "Metadata and Data in C"
description: Metadata and Data in C
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to [meta_data_and_data_python.md](meta_data_and_data_python.md), but in C.

# Solution

## 1. check the c program

```c
struct cimg_header
{
    char magic_number[4];
    uint8_t version;
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

    if (cimg.header.magic_number[0] != '<' || cimg.header.magic_number[1] != '@' || cimg.header.magic_number[2] != 'N' || cimg.header.magic_number[3] != 'r')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 1)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (cimg.header.width != 44)
    {
        puts("ERROR: Incorrect width!");
        exit(-1);
    }

    if (cimg.header.height != 24)
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

    if (won) win();

}
```

## 2. create a proper cimg file based (1)

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"<@Nr"
    version = 1
    version = version.to_bytes(1, "little")
    width = 44
    bwidth = width.to_bytes(2, "little")
    height = 24
    bheight = height.to_bytes(2, "little")
    
    data = bytes([1 for _ in range(width*height)])

    f.write(magic)
    f.write(version)
    f.write(bwidth)
    f.write(bheight)
    f.write(data)
```

## 3. run cimg

```
hacker@reverse-engineering~metadata-and-data-c:/challenge$ ./cimg ~/flag.cimg 
pwn.college{4lffrR0mkM-jbvWDAkwLZE8JQ4G.0lMxUjNxwCM0YjMyEzW}
```
