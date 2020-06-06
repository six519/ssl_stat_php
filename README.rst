ssl_stat_php
============

PHP C Language Extension To Get SSL Certificate Information From URL

Install Dependency (Ubuntu)
===========================
::

    apt install libcurl4-openssl-dev php-curl

Building & Installing
=====================
::

    composer require six519/ssl_stat:dev-master
    cd vendor/six519/ssl_stat/ext/
    phpize
    ./configure --enable-ssl_stat
    make
    sudo make install

Enabling
========

add entry to php.ini file `extension=/<PATH TO FILE>/ssl_stat.so`

Testing
=======
::

    php -dextension=ssl_stat.so -a

PHP Sample Usage
================
::

    $info = ssl_stat_check("https://example.com");