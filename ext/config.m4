PHP_ARG_ENABLE(ssl_stat, whether to enable ssl_stat support,
[ --enable-ssl_stat   Enable ssl_stat support])

if test "$PHP_SSL_STAT" = "yes"; then
    AC_DEFINE(HAVE_SSL_STAT, 1, [Whether you have ssl_stat])
    PHP_NEW_EXTENSION(ssl_stat, ssl_stat.c, $ext_shared)
fi