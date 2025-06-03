<?php 

namespace App\Utilities;

use App\Models\User;
use Illuminate\Support\Str;

class Ldap
{
    private static $initialized = false;
    private static $ldapPeopleOu;
    private static $ldapBaseDn;
    private static $ldapHost;
    private static $ldapPort;
    private static $ldapBindDn;
    private static $ldapBindPassword;

    private static function init()
    {
        if (!self::$initialized) {
            self::$ldapPeopleOu = config('ldap.people_ou');
            self::$ldapBaseDn = config('ldap.base_dn');
            self::$ldapHost = config('ldap.host');
            self::$ldapPort = config('ldap.port');
            self::$ldapBindDn = config('ldap.bind_dn');
            self::$ldapBindPassword = config('ldap.bind_password');
            self::$initialized = true;
        }
    }
    
    public static function bind($username, $password): bool
    {
        self::init();
        $dn = "uid={$username}," . self::$ldapPeopleOu . "," . self::$ldapBaseDn;
        $ldapConn = ldap_connect(self::$ldapHost, self::$ldapPort);

        ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

        return @ldap_bind($ldapConn, $dn, $password);
    }

    public static function syncUserFromLdap($user, $type, $password = null)
    {
        self::init();
        if (!$ldapConnection = self::connectToLdap()) {
            return null;
        }

        $dn = "uid={$user->username}," . self::$ldapPeopleOu . "," . self::$ldapBaseDn;
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
        self::init();
        $ldapConn = ldap_connect(self::$ldapHost, self::$ldapPort);
        
        if (!$ldapConn) {
            return null;
        }

        ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

        $bindDn = self::$ldapBindDn;
        $bindPw = self::$ldapBindPassword;
        
        if (!@ldap_bind($ldapConn, $bindDn, $bindPw)) {
            return null;
        }
        
        return $ldapConn;
    }

    public static function listLdapUsers(): array
    {
        self::init();
        $conn = self::connectToLdap();

        if (!$conn) return [];

        $baseDn = self::$ldapPeopleOu . ',' . self::$ldapBaseDn;
        $filter = '(objectClass=person)';
        $attributes = [
            'uid', 
            'cn', 
            'employeeNumber', 
            'givenName',
            'mail', 
            'title', 
            'joinDate', 
            'alternateEmail', 
            'activeStatus'
        ];

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

    public static function deleteLdapUser($username): bool
    {
        self::init();
        if (!$ldapConnection = self::connectToLdap()) {
            return false;
        }

        $dn = "uid={$username}," . self::$ldapPeopleOu . "," . self::$ldapBaseDn;
        
        // Check if user exists first
        $check = @ldap_read($ldapConnection, $dn, '(objectClass=*)');
        if (!$check) {
            return false; // User doesn't exist
        }

        return @ldap_delete($ldapConnection, $dn);
    }
}
