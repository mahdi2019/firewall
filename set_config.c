#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
int main()
{
    int k;
    char config_mode[15];
    char read_from_file[25];
    FILE* config_file;
    config_file = fopen("config.txt", "r");
    if (!config_file)
    {
        perror("Failed to open the file...");
        return errno;
    }
    fgets(read_from_file, 14, config_file);
    sscanf(read_from_file,"%s", config_mode);
    printf("Config Mode:%s\n",config_mode);

    int fd = open("/dev/Mfirewall", O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open the device...");
        return errno;
    }
    int ret = write(fd, read_from_file, strlen(read_from_file));
    if (ret < 0)
    {
        perror("Failed to write the message to the device.");
        return errno;
    }
    while(fgets(read_from_file, 24, config_file))
    {
        read_from_file[strlen(read_from_file)-1]='\0';
        printf("IP : %s is being sent down to the kernel\n", read_from_file);
        sleep(1);
        int ret = write(fd, read_from_file, strlen(read_from_file));
        if (ret < 0)
        {
            perror("Failed to write the message to the device.");
            return errno;
        }
    }
    return 0;
}