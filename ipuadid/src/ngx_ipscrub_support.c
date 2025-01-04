// Support library for ipscrub module.
// Copyright Mason Simon 2018

#include "ngx_ipscrub_support.h"

#if (NGX_FREEBSD || NGX_SOLARIS || NGX_DARWIN)
// arc4random is built-in on these platforms.
#elif (NGX_LINUX)
#include <bsd/stdlib.h>
#else
// TODO: test using libbsd on Windows.
#error ipscrub requires arc4random_buf.
#endif

// null_terminate allocates a new, null-terminated string based on input.
ngx_int_t null_terminate(ngx_pool_t *pool, ngx_str_t input, u_char **out)
{
  *out = ngx_pnalloc(pool, input.len + 1);
  if (*out == NULL) {
      return NGX_ERROR;
  }
  (void) ngx_cpymem(*out, input.data, input.len);
  (*out)[input.len] = '\0';

  return NGX_OK;
}

// concat concatenates prefix and suffix then null-terminates the result.
ngx_int_t concat(ngx_pool_t *pool, ngx_str_t prefix, ngx_str_t suffix, u_char **out)
{
  // Allocate.
  *out = ngx_pnalloc(pool, prefix.len + suffix.len + 1);
  if (*out == NULL) {
      return NGX_ERROR;
  }

  // Write prefix.
  (void) ngx_cpymem(*out, prefix.data, prefix.len);

  // Write suffix.
  (void) ngx_cpymem(*out + prefix.len, suffix.data, suffix.len);

  // Terminate.
  (*out)[prefix.len + suffix.len] = '\0';

  return NGX_OK;
}

// concat4 concatenates four arguments, then null-terminates the result.
ngx_int_t concat4(ngx_pool_t *pool, ngx_str_t a, ngx_str_t b, ngx_str_t c, ngx_str_t d, u_char **out)
{
  // Allocate.
  *out = ngx_pnalloc(pool, a.len + b.len + c.len + d.len + 1);
  if (*out == NULL) {
      return NGX_ERROR;
  }

  // Write prefix.
  u_char *cursor=ngx_cpymem(*out, a.data, a.len);
  // append and move writing cursor
  cursor = ngx_cpymem(cursor, b.data, b.len);
  // ditto
  cursor = ngx_cpymem(cursor, c.data, c.len);
  // ...
  cursor = ngx_cpymem(cursor, d.data, d.len);

  // Terminate.
  *cursor = '\0';

  return NGX_OK;
}

// randbytes fills out with secure random bytes.
// Return value of NGX_OK indicates success.
// Return value of NGX_ERROR indicates error.
ngx_int_t randbytes(u_char *out, int num_bytes) {
  if (out == NULL) {
    return NGX_ERROR;
  }
  if (num_bytes < 1 || num_bytes > 64) {
    // Values outside these bounds may indicate parameter usage mistake.
    return NGX_ERROR;
  }

  do{
	  arc4random_buf(out, num_bytes);
  }while(ngx_strlen(out)<num_bytes); // ensure there is no \0 char among random data

  return NGX_OK;
}
