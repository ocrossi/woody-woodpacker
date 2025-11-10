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
