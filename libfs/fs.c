#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#include "disk.h"
#include "fs.h"

// Super block specific definitions
#define SIGNATURE       "ECS150FS"

// FAT specific definitions
#define FAT_EOC         0xFFFF
#define FAT_EMPTY	    0

// Root directory specific definitions
#define MAX_FILE_NUM    128

// Error handling definitions
#define ERROR          -1
#define NO_ERROR        0

// Non-specific definitions
#define ONE_ENTRY       1

// Bound of fd tabke
#define FD_UPPER_BOUND  31
#define FD_LOWER_BOUND  0

struct __attribute__((__packed__)) sblock
{
    char sig[8];

    uint16_t tot_blocks;

    uint16_t root_index;

    uint16_t dblock_index;
    uint16_t dblock_num;

    uint8_t FAT_num;

    int8_t padding[4079];
};

struct __attribute__((__packed__)) rdir_entry
{
    char file_name[16];
    int32_t file_size;   //uint32_t?

    uint16_t first_dblock_index;

    int8_t padding[10];
};

// Used in phase 3
struct __attribute__((__packed__)) file_descriptor
{
    int fd;           // The identification code for this particular file descriptor
    int file_id;      // The file number we are accessing
    unsigned offset;  // The offset in the file we are accessing
};

typedef struct sblock sblock_t;
typedef struct rdir_entry rdir_entry_t;
typedef struct file_descriptor file_descriptor_t;


// Master Data Structure;
struct __attribute__((__packed__)) v_disk
{
    sblock_t sblock;
    uint16_t (*FAT_table)[2048];
    // ^ Should result in:
    // FAT BLOCK #1: 2048 Entries (each entry is 16 bits (2 bytes) so total is 4096 bytes)
    // FAT BLOCK #2: 2048 Entries
    // ...
    // FAT BLOCK #n: 2048 Entries

    rdir_entry_t rdir_table[128];

    // Separate from main disk, is never stored persistently or written to any file
    file_descriptor_t fd_table[32];
};

typedef struct v_disk v_disk_t;

// Global Virtual Disk
v_disk_t disk;

int common_error_check(bool file, const char *filename, bool f_desc, int fd) {

    bool success    = true;
    int retval      = 0;

    retval = block_disk_count();

    if(retval == ERROR) {
        success = false;
    }

    if(file) {
        if(filename == NULL) {
            success = false;
        }

        if(strlen(filename) == 0 || strlen(filename) > FS_FILENAME_LEN) {
            success = false;
        }
    }

    if(f_desc) {
        /* Out of bound */
        if (fd < FD_LOWER_BOUND || fd > FD_UPPER_BOUND) {
            success = false;
        }

        /* Not currently open */
        else if (disk.fd_table[fd].fd == -1 || disk.fd_table[fd].file_id == -1) {
            success = false;
        }

    }

    if(!success) {
        return ERROR;
    }

    return NO_ERROR;
}

int fs_mount(const char *diskname)
{
    int retval      = 0; 
    int block_index = 0;
    int table_index = 0;

    // Start by opening the virtual disk
    retval = block_disk_open(diskname);
    if(retval == ERROR) {
        return ERROR;
    }

    retval = common_error_check(false, "N/A", false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    // Next read in the first block (i.e. the Super Block)
    retval = block_read(block_index, &(disk.sblock));
    block_index++;
    if(retval == ERROR) {
        return ERROR;
    }

    // Check to make sure the signature matches
    int block_count = block_disk_count();
    retval = memcmp(SIGNATURE, disk.sblock.sig, 8);
    if(retval == ERROR || disk.sblock.tot_blocks != block_count) {
        return ERROR;
    }

    disk.FAT_table = malloc(sizeof(int16_t[2048]) * disk.sblock.FAT_num); // Modified, see note above
    if(disk.FAT_table == NULL) {
        free(disk.FAT_table);
        return ERROR;
    }

    int start_of_FAT = block_index;

    while(block_index < (disk.sblock.FAT_num + start_of_FAT))
    {
        table_index = block_index - 1;

        retval = block_read(block_index, &(disk.FAT_table[table_index]));
        block_index++;

        if(retval == ERROR) {
            free(disk.FAT_table);
            return ERROR;
        }
    }

    retval = block_read(disk.sblock.root_index, &(disk.rdir_table));
    block_index++;
    if(retval == ERROR) {
        free(disk.FAT_table);
        return ERROR;
    }

    for(int i = 0; i < 32; i++) {
        disk.fd_table[i].fd      = -1;
        disk.fd_table[i].file_id = -1;
        disk.fd_table[i].offset  =  0;
    }

    return NO_ERROR;
}

int fs_umount(void)
{
    int retval      = 0;
    int block_index = 0;
    int table_index = 0;

    retval = common_error_check(false, "N/A", false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    retval = block_write(block_index, &(disk.sblock));
    block_index++;
    if(retval == ERROR) {
        return ERROR;
    }

    int start_of_FAT = block_index;

    while(block_index < (disk.sblock.FAT_num + start_of_FAT)) {
        table_index = block_index - 1;
        retval = block_write(block_index, &(disk.FAT_table[table_index][0]));
        block_index++;

        if(retval == ERROR) {
            free(disk.FAT_table);
            return ERROR;
        }
    }

    retval = block_write(block_index, &(disk.rdir_table));
    block_index++;
    if(retval == ERROR) {
        return ERROR;
    }

    free(disk.FAT_table);

    retval = block_disk_close();
    if(retval == ERROR) {
        return ERROR;
    }

    memset(disk.sblock.sig, 0, 8);

    disk.sblock.tot_blocks      = 0;
    disk.sblock.FAT_num         = 0;
    disk.sblock.root_index      = 0;
    disk.sblock.dblock_index    = 0;
    disk.sblock.dblock_num      = 0;

    return NO_ERROR;
}

int num_free_FAT(void) {

    int num_free    = 0;
    uint16_t row    = 0;
    uint16_t col    = 0;
    int max_col     = 0;

    for(; row < disk.sblock.FAT_num; row += ONE_ENTRY) {
        
        if(row + 1 == disk.sblock.FAT_num) { // i.e. the last row
            max_col = (disk.sblock.dblock_num - (row*2048)) % (2048 + 1);
        } else {
            max_col = 2048;
        }

        for (; col < max_col; col += ONE_ENTRY) {
            if (disk.FAT_table[row][col] == FAT_EMPTY) {
                num_free += ONE_ENTRY;
            }
        }

        col = 0;
    }

    return num_free;
}

int num_free_RDIR(void) {

    int num_free    = 0;
    uint16_t i      = 0;

    for(; i < MAX_FILE_NUM; i += ONE_ENTRY) {
        if(disk.rdir_table[i].file_name[0] == '\0') {
            num_free += ONE_ENTRY;
        }
    }

    return num_free;
}

int fs_info(void)
{
    int retval      = 0;
    int FAT_free    = 0;
    int RDIR_free   = 0;

    retval = common_error_check(false, "N/A", false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    FAT_free = num_free_FAT();
    RDIR_free = num_free_RDIR();

    printf("FS Info:\n");

    printf("total_blk_count=%u\n",     disk.sblock.tot_blocks                           );
    printf("fat_blk_count=%u\n",       disk.sblock.FAT_num                              );
    printf("rdir_blk=%u\n",            disk.sblock.root_index                           );
    printf("data_blk=%u\n",            disk.sblock.dblock_index                         );
    printf("data_blk_count=%u\n",      disk.sblock.dblock_num                           );
    printf("fat_free_ratio=%u/%u\n",   FAT_free,                 disk.sblock.dblock_num );
    printf("rdir_free_ratio=%u/%u\n",  RDIR_free,                MAX_FILE_NUM           );


    return NO_ERROR;
}

/**
 * fs_create - Create a new file
 * @filename: File name
 *
 * Create a new and empty file named @filename in the root directory of the
 * mounted file system. String @filename must be NULL-terminated and its total
 * length cannot exceed %FS_FILENAME_LEN characters (including the NULL
 * character).
 *
 * Return: -1 if @filename is invalid, if a file named @filename already exists,
 * or if string @filename is too long, or if the root directory already contains
 * %FS_FILE_MAX_COUNT files. 0 otherwise.
        if(disk.rdir_table[rdir_index].file_name[0] != '\0') {
            // printf("file: %s, ",   disk.rdir_table[rdir_index].file_name);
            // printf("size: %u, ",   disk.rdir_table[rdir_index].file_size);
            // printf("data_blk: %u", disk.rdir_table[rdir_index].first_dblock_index);
            // printf("\n");
*/
int fs_create(const char *filename)
{
    int retval      = 0;
    int rdir_index  = 0;
    int row_index   = 0;
    int col_index   = 1;
    int max_col     = 0;

    bool empty_rdir = false;
    bool empty_fat  = false;

    retval = common_error_check(true, filename, false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    while(rdir_index < FS_FILE_MAX_COUNT) {
        if(strcmp(disk.rdir_table[rdir_index].file_name, filename) == 0) {
            return ERROR;
        }
        rdir_index++;
    }

    rdir_index = 0;

    while(rdir_index < FS_FILE_MAX_COUNT)
    {
        if(strcmp(disk.rdir_table[rdir_index].file_name, filename) == 0) {
            // printf("File Already Exists Error\n");
            return ERROR;
        }

        else if(disk.rdir_table[rdir_index].file_name[0] == '\0' && empty_rdir == false)
        {
            empty_rdir = true;

            for(; row_index < disk.sblock.FAT_num; row_index++) {
                if(row_index + 1 == disk.sblock.FAT_num) { 
                    max_col = (disk.sblock.dblock_num - (row_index*2048)) % (2048 + 1);
                } else {
                    max_col = 2048;
                }

                for(; col_index < max_col; col_index++) 
                {
                    if(disk.FAT_table[row_index][col_index] == FAT_EMPTY)
                    {
                        disk.rdir_table[rdir_index].first_dblock_index = (row_index * 2048) + col_index;
                        disk.FAT_table[row_index][col_index] = FAT_EOC;
                        disk.rdir_table[rdir_index].file_size = 0;
                        
                        strcpy(disk.rdir_table[rdir_index].file_name, filename);

                        empty_fat = true;
                        break;
                    } 

                }
                
                col_index = 0;

                if(empty_fat == true)
                    break;
            }

            break;
        }

        rdir_index += ONE_ENTRY;
    }

    
    if(!empty_fat && empty_rdir == true) {
        disk.rdir_table[rdir_index].file_size = 0;
        disk.rdir_table[rdir_index].first_dblock_index = FAT_EOC;
        strcpy(disk.rdir_table[rdir_index].file_name, filename);
    }

    if(!empty_rdir) {
        return ERROR;
    }

    return NO_ERROR;
}

/**
 * fs_delete - Delete a file
 * @filename: File name
 *
 * Delete the file named @filename from the root directory of the mounted file
 * system.
 *
 * Return: -1 if @filename is invalid, if there is no file named @filename to
 * delete, or if file @filename is currently open. 0 otherwise.
 */

int fs_delete(const char *filename)
{
    int retval          = 0;
    int rdir_index      = 0;

    int fat_index       = 0;
    int next_fat_index  = 0;

    int row_index       = 0;
    int col_index       = 0;

    bool success        = false;

    retval = common_error_check(true, filename, false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    for(; rdir_index < FS_FILE_MAX_COUNT; rdir_index++)
    {
        if(strcmp(disk.rdir_table[rdir_index].file_name, filename) == 0)
        {
            for(int fd = 0; fd < FS_OPEN_MAX_COUNT; fd++) 
            {
                if(disk.fd_table[fd].file_id == rdir_index) {

                    return ERROR;
                }
            }

            fat_index = disk.rdir_table[rdir_index].first_dblock_index;
            row_index = floor(fat_index / 2048);
            col_index = fat_index % 2048;

            memset(disk.rdir_table[rdir_index].file_name, 0, FS_FILENAME_LEN);
            disk.rdir_table[rdir_index].file_name[0] = '\0'; // Added, remove if error occurs
            disk.rdir_table[rdir_index].file_size = -1;
            disk.rdir_table[rdir_index].first_dblock_index = -1;

            if(fat_index == FAT_EOC) {
                success = true;
                break;
            }

            while(disk.FAT_table[row_index][col_index] != FAT_EOC)
            {
                next_fat_index = disk.FAT_table[row_index][col_index];

                disk.FAT_table[row_index][col_index] = FAT_EMPTY;
                row_index = floor(next_fat_index / 2048);
                col_index = next_fat_index % 2048;

                
                if (disk.FAT_table[row_index][col_index] == FAT_EMPTY)
                    break;
            }

            if(disk.FAT_table[row_index][col_index] == FAT_EOC) {
                disk.FAT_table[row_index][col_index] = FAT_EMPTY;
            }

            success = true;
            break;
        }
    }

    if(!success) {
        return ERROR;
    }

    return NO_ERROR;
}


int fs_ls(void)
{
    int retval      = 0;
    int rdir_index  = 0;

    retval = common_error_check(false, "N/A", false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    printf("FS Ls:\n");

    for(; rdir_index < FS_FILE_MAX_COUNT; rdir_index++)
    {
        if(disk.rdir_table[rdir_index].file_name[0] != '\0') {
            printf("file: %s, ",   disk.rdir_table[rdir_index].file_name);
            printf("size: %u, ",   disk.rdir_table[rdir_index].file_size);
            printf("data_blk: %u", disk.rdir_table[rdir_index].first_dblock_index);
            printf("\n");
        }
    }

    return NO_ERROR;
}

/**
 * fs_open - Open a file
 * @filename: File name
 *
 * Open file named @filename for reading and writing, and return the
 * corresponding file descriptor. The file descriptor is a non-negative integer
 * that is used subsequently to access the contents of the file. The file offset
 * of the file descriptor is set to 0 initially (beginning of the file). If the
 * same file is opened multiple files, fs_open() must return distinct file
 * descriptors. A maximum of %FS_OPEN_MAX_COUNT files can be open
 * simultaneously.
 *
 * Return: -1 if @filename is invalid, there is no file named @filename to open,
 * or if there are already %FS_OPEN_MAX_COUNT files currently open. Otherwise,
 * return the file descriptor.
 */

int fs_open(const char *filename)
{
    int retval      = 0;
    int fd_index    = 0;
    int rdir_index  = 0;

    bool fd_table_free  = false;
    bool success        = false;    
    retval = common_error_check(true, filename, false, -1);
    if(retval == ERROR) {
        return ERROR;
    }

    for(; rdir_index < FS_FILE_MAX_COUNT; rdir_index++) {
        retval = strcmp(disk.rdir_table[rdir_index].file_name, filename);
        if (retval == 0) {
            while(fd_index < FS_OPEN_MAX_COUNT) {

                if(disk.fd_table[fd_index].fd == -1) {

                    fd_table_free = true;

                    disk.fd_table[fd_index].fd      = fd_index;
                    disk.fd_table[fd_index].file_id = rdir_index;
                    disk.fd_table[fd_index].offset  = 0;
                    break;
                }

                fd_index += ONE_ENTRY;
            }

            if(fd_table_free) {
                success = true;
            }

            break;
        }
    }

    if(!success) {
        //printf("Failure Error\n");
        return ERROR;
    }

    return fd_index;
}

int fs_close(int fd)
{
    int retval = common_error_check(false, "N/A", true, fd);
    if(retval == ERROR) {
        //printf("fs_close cec failed \n");
        return ERROR;
    }

    /* currently open, close it now */
    disk.fd_table[fd].fd      = -1;
    disk.fd_table[fd].file_id = -1;
    disk.fd_table[fd].offset  =  0;

    return NO_ERROR;
}

int fs_stat(int fd)
{
    int size_of_file = 0;
    int rdir_file_index = 0;

    int retval = common_error_check(false, "N/A", true, fd);

    if(retval == ERROR) {
        // printf("fs_stat cec failed \n");
        return ERROR;
    }

    rdir_file_index = disk.fd_table[fd].file_id;

    //// printf("%d \n", rdir_file_index);
    size_of_file = disk.rdir_table[rdir_file_index].file_size;
    //// printf("%d \n", size_of_file);

    return size_of_file;
}

int fs_lseek(int fd, size_t offset)
{
    int rdir_index = disk.fd_table[fd].file_id;
    int retval = common_error_check(false, "N/A", true, fd);
    if(retval == ERROR) {
        // printf("fs_lseek cec failed \n");
        return ERROR;
    }

    if(offset > (size_t) disk.rdir_table[rdir_index].file_size) {
        return ERROR;
    }

    disk.fd_table[fd].offset = offset;

    return NO_ERROR;
}

/**
 * fs_write - Write to a file
 * @fd: File descriptor
 * @buf: Data buffer to write in the file
 * @count: Number of bytes of data to be written
 *
 * Attempt to write @count bytes of data from buffer pointer by @buf into the
 * file referenced by file descriptor @fd. It is assumed that @buf holds at
 * least @count bytes.
 *
 * When the function attempts to write past the end of the file, the file is
 * automatically extended to hold the additional bytes. If the underlying disk
 * runs out of space while performing a write operation, fs_write() should write
 * as many bytes as possible. The number of written bytes can therefore be
 * smaller than @count (it can even be 0 if there is no more space on disk).
 *
 * Return: -1 if file descriptor @fd is invalid (out of bounds or not currently
 * open). Otherwise return the number of bytes actually written.
 */
int fs_write(int fd, void *buf, size_t count)
{
    int retval                      = 0;                                                // Common Variable for Error Checking

    const size_t initial_count      = count;                                            // Keep Track Of Total Count

    uint16_t db_start_index         = disk.sblock.dblock_index;                         // Block Index of First Data Block (i.e. after FAT Blocks)
    int rdir_index                  = disk.fd_table[fd].file_id;                        // Root Directory Index (i.e. which file is it)
    unsigned offset                 = disk.fd_table[fd].offset;                         // File Descriptor's Current Offset
    int db_index                    = disk.rdir_table[rdir_index].first_dblock_index;   // File's Current Data Block
    int next_db_index               = 0;
    int overall_block_index         = db_index + db_start_index;                        // Actual Index of Block (NOT JUST RELATIVE TO OTHER DATA BLOCKS)
    int row_index                   = 0;                                                // Row Index for FAT Table
    int col_index                   = 0;                                                // Col Index for FAT Table
    int max_col                     = 0;

    size_t bytes_written            = 0;                                                // Number of bytes read by the file

    int fg = false;
    bool last_block = false;

    retval = common_error_check(false, "N/A", true, fd);
    if(retval == ERROR) {
        return ERROR;
    }        
    
    if(db_index == FAT_EOC) {
        return bytes_written;
    }
    
    row_index = floor(db_index / 2048);
    col_index = db_index % 2048;

    if(disk.rdir_table[rdir_index].file_size == 0 && count == 0) {
        disk.FAT_table[row_index][col_index] = FAT_EMPTY;
        disk.rdir_table[rdir_index].first_dblock_index = FAT_EOC;
        return bytes_written;
    }

    if(offset > BLOCK_SIZE) {

        // Get current data block
        unsigned db_offset = offset;

        while(floor(db_offset/BLOCK_SIZE) > 0) {

            db_index = disk.FAT_table[row_index][col_index];

            overall_block_index = db_index + db_start_index;

            db_offset -= BLOCK_SIZE;
        }
    }

    //Simplest case, offset = 0, count < BLOCK_SIZE
    if(offset == 0 && count <= BLOCK_SIZE) {

        retval = block_write(overall_block_index, buf);
        if(retval == ERROR) {
            return ERROR;
        }

        offset += count;
        bytes_written += count;
    }

    // More Complex Cases
    else {
        while(bytes_written < initial_count) {

            char bounce[BLOCK_SIZE];

            if(num_free_FAT() == 0) {
                last_block = true;
            }

            if (disk.FAT_table[row_index][col_index] == FAT_EOC && (initial_count - bytes_written) > BLOCK_SIZE) {
                // ALLOCATE MORE DATA BLOCKS
                
                for(int next_row_index = 0; next_row_index < disk.sblock.FAT_num; next_row_index++) {
                    if(next_row_index + 1 == disk.sblock.FAT_num) { 
                        max_col = (disk.sblock.dblock_num - (next_row_index*2048)) % (2048 + 1);

                    } 
                    
                    else {
                        max_col = 2048; 
                    }

 
                    for (int next_col_index = 0; next_col_index < max_col; next_col_index++) { // used to be: < disk.sblock.dblock_num
                        if (disk.FAT_table[next_row_index][next_col_index] == FAT_EMPTY) { // FAT_EMPTY = 0
                            

                            disk.FAT_table[row_index][col_index] = (next_row_index * 2048) + next_col_index; 
                            disk.FAT_table[next_row_index][next_col_index] = FAT_EOC;

                            next_db_index = disk.FAT_table[row_index][col_index];
                           
                            fg = true;
                            break;
                        }
                    }
                    if (fg==true)
                        break;
                }

            } else {
                next_db_index = disk.FAT_table[row_index][col_index];
            }

           
            retval = block_read(overall_block_index, bounce);
            if(retval == ERROR) {
                return ERROR;
            }


            if (BLOCK_SIZE - (offset % BLOCK_SIZE) < initial_count - bytes_written)
                count = BLOCK_SIZE - (offset % BLOCK_SIZE);
            else
                count = initial_count - bytes_written;

            memcpy(&(bounce[offset % BLOCK_SIZE]), (buf + bytes_written), count);

            
            retval = block_write(overall_block_index, bounce); 
            if(retval == ERROR) {
                return ERROR;
            }            
            
            bytes_written += count;
            offset += count;

            db_index = next_db_index;
            row_index = floor(db_index / 2048);
            col_index = db_index % 2048;

            fg = false;
            
            overall_block_index = db_index + db_start_index;

            if (last_block && bytes_written < initial_count) // Let's try it now, this should work, the 4096 was messing things up I think
                break;
        }
    }

    disk.rdir_table[rdir_index].file_size += bytes_written;
    disk.fd_table[fd].offset = offset;

    return bytes_written;
}

/**
 * fs_read - Read from a file
 * @fd: File descriptor
 * @buf: Data buffer to be filled with data
 * @count: Number of bytes of data to be read
 *
 * Attempt to read @count bytes of data from the file referenced by file
 * descriptor @fd into buffer pointer by @buf. It is assumed that @buf is large
 * enough to hold at least @count bytes.
 *
 * The number of bytes read can be smaller than @count if there are less than
 * @count bytes until the end of the file (it can even be 0 if the file offset
 * is at the end of the file). The file offset of the file descriptor is
 * implicitly incremented by the number of bytes that were actually read.
 *
 * Return: -1 if file descriptor @fd is invalid (out of bounds or not currently
 * open). Otherwise return the number of bytes actually read.
 */
int fs_read(int fd, void *buf, size_t count)
{
    int retval                  = 0;                                                // Common Variable for Error Checking

    const size_t initial_count  = count;                                            // Keep Track Of Total Count

    uint16_t db_start_index     = disk.sblock.dblock_index;                         // Block Index of First Data Block (i.e. after FAT Blocks)
    int rdir_index              = disk.fd_table[fd].file_id;                        // Root Directory Index (i.e. which file is it)
    unsigned offset             = disk.fd_table[fd].offset;                         // File Descriptor's Current Offset
    size_t size_of_file         = disk.rdir_table[rdir_index].file_size;            // File's Current Size
    int db_index                = disk.rdir_table[rdir_index].first_dblock_index;   // File's Current Data Block
    int overall_block_index     = db_index + db_start_index;                        // Actual Index of Block (NOT JUST RELATIVE TO OTHER DATA BLOCKS)
    int row_index               = 0;                                                // Row Index for FAT Table
    int col_index               = 0;                                                // Col Index for FAT Table
    int remaining_bytes_in_file = 0;                                                // Remaining Bytes in the File (Bytes that remain past the offset)

    size_t bytes_read           = 0;                                                // Number of bytes read by the file

    char bounce[BLOCK_SIZE];

    retval = common_error_check(false, "N/A", true, fd);
    if(retval == ERROR) {
        return ERROR;
    }

    if(db_index == FAT_EOC) {
        return bytes_read;
    }

    if(offset > BLOCK_SIZE) {
        unsigned db_offset = offset;

        while(floor(db_offset/BLOCK_SIZE) > 0) {
            row_index = floor(db_index / 2048);
            col_index = db_index % 2048;
       
            db_index = disk.FAT_table[row_index][col_index];

            overall_block_index = db_index + db_start_index;

            db_offset -= BLOCK_SIZE;
        }
    }

    // Simplest Case: offset is 0 and count is less than or equal to 4096
    if(offset == 0 && count <= BLOCK_SIZE) {

        retval = block_read(overall_block_index, bounce);
        if(retval == ERROR) {
            return ERROR;
        }

        memcpy(buf, bounce, count);

        offset += count;
        bytes_read += count;
    }

        // More Complex Cases
    else {

        while(bytes_read < initial_count) {
            remaining_bytes_in_file = size_of_file - offset;

            if(remaining_bytes_in_file <= 0) {
                break;
            }

            retval = block_read(overall_block_index, bounce);
            if(retval == ERROR) {
                return ERROR;
            }
            // KEEP FOR NOW
            if(BLOCK_SIZE - (offset % BLOCK_SIZE) < initial_count - bytes_read) {
                count = BLOCK_SIZE - (offset % BLOCK_SIZE);
            } else {
                count = initial_count - bytes_read;
            }

            memcpy(buf + bytes_read, bounce + (offset % BLOCK_SIZE), count);

            // FIND NEXT BLOCK IF APPLICABLE.
            row_index = floor(db_index / 2048);

            col_index = db_index % 2048;

            db_index = disk.FAT_table[row_index][col_index];

            overall_block_index = db_index + db_start_index;

            offset += count;
            bytes_read += count;

            if(db_index == FAT_EOC) { 
                break;
            }

        }

    }
    disk.fd_table[fd].offset = offset;

    return bytes_read;
}

