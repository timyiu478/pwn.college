---
tags: ["Reverse Engineering"]
title: "Behold the cIMG! C"
description: Behold the cIMG! C
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to [behold_the_cimg_python.md](behold_the_cimg_python.md), but in C.

# Solution

## 1. read the C code

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
    uint8_t version;
    uint32_t width;
    uint64_t height;
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

void display(struct cimg *cimg, pixel_t *data)
{
    int idx = 0;
    for (int y = 0; y < cimg->header.height; y++)
    {
        for (int x = 0; x < cimg->header.width; x++)
        {
            idx = (0+y)*((cimg)->header.width) + ((0+x)%((cimg)->header.width));
            putchar(data[y * cimg->header.width + x].ascii);

        }
        puts("");
    }

}

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

    display(&cimg, data);

    int num_nonspace = 0;
    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii != ' ') num_nonspace++;
    }
    if (num_nonspace != 275) won = 0;

    if (won) win();

}
```

## 2. creat .cimg file

```python
     1	import struct
     2	
     3	with open("flag.cimg", "wb") as f:
     4	    magic = b"cIMG"
     5	    version = 1
     6	    version = version.to_bytes(1, "little")
     7	    width = b"\x11\x00\x00\x00"
     8	    height = b"\x11\x00\x00\x00\x00\x00\x00\x00"
     9	
    10	    arr = [95 for _ in range(17*17)]
    11	
    12	    for i in range(17*17-275):
    13	        arr[i] = 32
    14	
    15	    data = bytes(arr)
    16	
    17	    f.write(magic)
    18	    f.write(version)
    19	    f.write(width)
    20	    f.write(height)
    21	    f.write(data)
```

## 3. run binary

```
hacker@reverse-engineering~behold-the-cimg-c:/challenge$ ./cimg ~/flag.cimg
              ___
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
pwn.college{gEhTPne8Fnc8WCMs0FAsMHVNAoI.0lNxUjNxwCM0YjMyEzW}
```
