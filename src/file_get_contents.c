#include "ft_nmap.h"

static void init_buff_result(char **buff, char **result)
{
	if (!(*buff = malloc(sizeof(**buff) * 1001)))
	{
		fprintf(stderr, RED "ft_nmap: can't malloc file buffer\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (!(*result = malloc(sizeof(**result))))
	{
		fprintf(stderr, RED "ft_nmap: can't malloc file content\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	*result[0] = '\0';
	ft_memset(*buff, 0, 1001);
}

static ssize_t loop_read(char **result, char **buff, int fd)
{
	ssize_t readed;
	int count;

	count = 0;
	while ((readed = read(fd, *buff, 1000)) > 0)
	{
		if (!(*result = ft_strjoin_free1(*result, *buff)))
		{
			fprintf(stderr, RED "ft_mnap: can't malloc file content\n" DEFAULT);
			exit(EXIT_FAILURE);
		}
		if ((count += readed) > 1024 * 1024)
		{
			fprintf(stderr, RED "ft_nmap: file too long\n", DEFAULT);
		}
		ft_memset(*buff, 0, 1001);
	}
 	return (readed);
}

static void check_error(ssize_t readed, char *file)
{
	if (readed == -1)
	{
		fprintf(stderr, RED "ft_nmap: error while reading '%s' file\n" DEFAULT, file);
		exit(EXIT_FAILURE);
	}
}

char *file_get_contents(char *file)
{
	ssize_t readed;
	char *result;
	char *buff;
	int fd;

	if ((fd = open(file, O_RDONLY)) == -1)
	{
		fprintf(stderr, RED "ft_nmap: can't open '%s' file\n" DEFAULT, file);
		exit(EXIT_FAILURE);
	}
	buff = NULL;
	result = NULL;
	init_buff_result(&buff ,&result);
	readed = loop_read(&result, &buff, fd);
	check_error(readed, file);
	free(buff);
	return (result);
}
