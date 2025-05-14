<?php 

namespace App\Utilities;

use App\Models\User;
use Illuminate\Support\Str;

class Utils
{
    public function generateUsername($name)
	{
		$temp = explode(' ', $name);
        $username = $name[0] . $temp[count($temp) - 1];
	    $username = strtolower($username);
	    $username = preg_replace('/[^A-Za-z0-9\.]/', '', $username);
	    $checkUsername = User::where('username', $username)->first();

	    if ($checkUsername) {
	        $username_with_inc = '';
	        $increment = 0;

	        // akan melakukan perulangan bmafazi02, bmafazi03 dst jika username yg digenerate diatas telah digunakan
	        while ($checkUsername) {
	            $increment++;
	            $username_with_inc = $username . str_pad($increment, 2, "0", STR_PAD_LEFT);
	            $checkUsername = User::where('username', $username_with_inc)->first();
	        }
	        
	        $username = $username_with_inc;
	    }

	    return $username;
	}
}