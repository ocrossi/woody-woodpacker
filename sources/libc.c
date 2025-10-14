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

int		ft_memcmp(const void *s1, const void *s2, size_t n)
{
	while (n--)
	{
		if (*(unsigned char*)s1 != *(unsigned char*)s2)
			return (*(unsigned char*)s1 - *(unsigned char*)s2);
		s1++;
		s2++;
	}
	return (0);
}

size_t	ft_strlen(const char *str)
{
	size_t i;

	i = 0;
	if (str == NULL)
		return (0);
	while (str[i])
		i++;
	return (i);
}
