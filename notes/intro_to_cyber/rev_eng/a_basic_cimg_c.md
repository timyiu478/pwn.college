---
tags: ["Reverse Engineering"]
title: "A Basic cIMG in C"
description: A Basic cIMG in C
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

It's time to upgrade to a new version of the cIMG, getting much closer to usurping the boring old image formats of the web. Spot what's different, understand what /challenge/cimg wants, and get the flag!

# Solution

## 1. read the c program

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
    uint16_t version;
    uint32_t width;
    uint8_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
#define COLOR_PIXEL_FMT "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"
typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_color_t;
typedef pixel_color_t pixel_t;

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
            printf("\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", data[y * cimg->header.width + x].r, data[y * cimg->header.width + x].g, data[y * cimg->header.width + x].b, data[y * cimg->header.width + x].ascii);

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

    if (cimg.header.version != 2)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (cimg.header.width != 26)
    {
        puts("ERROR: Incorrect width!");
        exit(-1);
    }

    if (cimg.header.height != 23)
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

    display(&cimg, data);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].r != 0x8c || data[i].g != 0x1d || data[i].b != 0x40) won = 0;
    }

    int num_nonspace = 0;
    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii != ' ') num_nonspace++;
    }
    if (num_nonspace != 598) won = 0;

    if (won) win();

}
```

## 2. create .cimg file

```python
     1	import struct
     2	
     3	with open("flag.cimg", "wb") as f:
     4	    magic = b"cIMG"
     5	    version = 2
     6	    version = version.to_bytes(2, "little")
     7	    width = 26
     8	    width = width.to_bytes(4, "little")
     9	    height = 23
    10	    height = height.to_bytes(1, "little")
    11	
    12	
    13	    f.write(magic)
    14	    f.write(version)
    15	    f.write(width)
    16	    f.write(height)
    17	
    18	    for i in range(26*23-598):
    19	       f.write(b"\x20\x20\x20\x20")
    20	    for i in range(598):
    21	       f.write(b"\x8c\x1d\x40\x30")
```

## 3. run cimg

```
hacker@reverse-engineering~a-basic-cimg-c:/challenge$ ./cimg ~/flag.cimg
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
00000000000000000000000000
pwn.college{8mROr43wGhqjR4TBJouZXToIwfx.0FOxUjNxwCM0YjMyEzW}
```
