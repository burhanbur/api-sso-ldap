<?php 

namespace App\Utilities;

use App\Models\User;
use Illuminate\Support\Str;

class Ldap
{
    public static function bind($username, $password): bool
    {
        $dn = "uid={$username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
        $ldapConn = ldap_connect(env('LDAP_HOST'), env('LDAP_PORT'));

        ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

        return @ldap_bind($ldapConn, $dn, $password);
    }

    public static function syncUserFromLdap($user, $type, $password = null)
    {
        if (!$ldapConnection = self::connectToLdap()) {
            return null;
        }

        $dn = "uid={$user->username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
        $entry = [
            'objectClass' => [
                'inetOrgPerson',
                'organizationalPerson',
                'person',
                'top',
                'uperPerson'
            ],
            'uid' => $user->username,
            'cn' => $user->full_name,
            'sn' => $user->full_name,
            'givenName' => $user->nickname,
            'mail' => $user->email,
            'title' => $user->title,
            'employeeNumber' => $user->code,
            'joinDate' => $user->join_date,
            'alternateEmail' => $user->alt_email,
            'activeStatus' => $user->status,
        ];

        // Create or update account LDAP server
        if ($type == 'store') {
            $entry['userPassword'] = self::hashLdapPassword($password);

            // Check if exists first (defensive)
            $check = @ldap_read($ldapConnection, $dn, '(objectClass=*)');
            if (!$check) {
                // @ldap_delete($ldapConnection, $dn);
                $success = @ldap_add($ldapConnection, $dn, $entry);
            }
        } else {
            $success = @ldap_modify($ldapConnection, $dn, $entry);
        }

        return $success ?? false;
    }

    public static function hashLdapPassword($password)
    {
        $salt = random_bytes(4);
        $hash = sha1($password . $salt, true);
        return '{SSHA}' . base64_encode($hash . $salt);
    }

    public static function connectToLdap()
    {
        $ldapConn = ldap_connect(env('LDAP_HOST'), env('LDAP_PORT'));
        
        if (!$ldapConn) {
            return null;
        }

        ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

        $bindDn = env('LDAP_BIND_DN');
        $bindPw = env('LDAP_BIND_PASSWORD');
        
        if (!@ldap_bind($ldapConn, $bindDn, $bindPw)) {
            return null;
        }
        
        return $ldapConn;
    }

    public static function listLdapUsers(): array
    {
        $conn = self::connectToLdap();

        if (!$conn) return [];

        $baseDn = env('LDAP_PEOPLE_OU') . ',' . env('LDAP_BASE_DN');
        $filter = '(objectClass=person)';
        $attributes = ['uid', 'cn', 'employeeNumber', 'givenName', 'cn', 'mail', 'title', 'joinDate', 'alternateEmail', 'activeStatus'];

        $search = ldap_search($conn, $baseDn, $filter, $attributes);
        $entries = ldap_get_entries($conn, $search);

        $users = [];

        for ($i = 0; $i < $entries['count']; $i++) {
            $users[] = [
                'uid' => $entries[$i]['uid'][0] ?? null,
                'employeeNumber' => $entries[$i]['employeenumber'][0] ?? null,
                'cn' => $entries[$i]['cn'][0] ?? null,
                'givenName' => $entries[$i]['givenname'][0] ?? null,
                'email' => $entries[$i]['mail'][0] ?? null,
                'alternateEmail' => $entries[$i]['alternateemail'][0] ?? null,
                'joinDate' => $entries[$i]['joindate'][0] ?? null,
                'title' => $entries[$i]['title'][0] ?? null,
                'activeStatus' => $entries[$i]['activestatus'][0] ?? null,
            ];
        }

        return $users;
    }
}
