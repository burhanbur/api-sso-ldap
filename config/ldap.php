<?php 

return [
    'bind_dn' => env('LDAP_BIND_DN', 'cn=admin,dc=universitaspertamina,dc=ac,dc=id'),
    'bind_password' => env('LDAP_BIND_PASSWORD', 'secret'),
    'host' => env('LDAP_HOST', '127.0.0.1'),
    'port' => env('LDAP_PORT', '389'),
    'base_dn' => env('LDAP_BASE_DN', 'dc=universitaspertamina,dc=ac,dc=id'),
    'people_ou' => env('LDAP_PEOPLE_OU', 'ou=people'),
];