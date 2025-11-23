#include "../includes/woody.h"

void	*ft_memset(void *b, int c, size_t len)
{
    void *ret;

    ret = b;
    while (len)
    {
        *(unsigned char *)b = c;
        b++;
        len--;
    }
    return (ret);
}

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
    void *ret;

    ret = dst;
    while (n)
    {
        *(char*)dst++ = *(char*)src++;
        n--;
    }
    return (ret);
}

int		ft_strcmp(const char *s1, const char *s2)
{
	int i;

	i = 0;
	while (s1[i] == s2[i] && (s1[i] || s2[i]))
		i++;
	return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}
