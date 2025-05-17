<?php 

namespace App\Utilities;

use App\Models\User;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Redis;
use Tymon\JWTAuth\Facades\JWTAuth;

class Utils
{
	private static $instance = null;

    /**
     * Returns the instance of the class
     *
     * This method implements the Singleton pattern
     * 
     * @return Utils
     */
    public static function getInstance()
    {
        if(self::$instance == null)
        {
            self::$instance = new Utils();
        }

        return self::$instance;
    }

    /**
     * Generate a username based on the given name and type
     *
     * Algorithm:
     * 1. Take the first character of the name and the last word of the name
     * 2. Convert to lowercase
     * 3. Remove all non-alphanumeric characters
     * 4. Check if the generated username has been used
     * 5. If yes, append a incrementing number to the username until it is unique
     * 
     * @param string $name The name to generate username from
     * @param string $type The type of user (e.g. staff, student, etc.)
     * @return string The generated username
     */
    public function generateUsername($name, $type = 'student')
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

    /**
     * Store a JWT token in Redis for a given user UUID
     *
     * The token is stored in three different ways:
     * 1. As a simple key-value pair with TTL (token details)
     * 2. As a mapping from token to user UUID (for fast lookup)
     * 3. As a sorted set with score = timestamp expired (for fast identification of valid tokens)
     *
     * @param string $uuid The user UUID
     * @param string $token The JWT token
     * @return void
     */
	public function storeTokenInRedis($uuid, $token)
    {
		$ttl = JWTAuth::factory()->getTTL() * 60;
		
		// 1. Simpan detail token dengan TTL individu
		Redis::setex("token_details:{$token}", $ttl, json_encode([
			'uuid' => $uuid,
			'created_at' => now()->timestamp
		]));
		
		// 2. Simpan mapping token ke user untuk pencarian cepat
		Redis::setex("token_to_user:{$token}", $ttl, $uuid);
		
		// 3. Tambahkan token ke sorted set dengan score = timestamp expired
		// Dengan sorted set, kita bisa mengidentifikasi token valid dengan membandingkan score dengan waktu sekarang
		$expiresAt = now()->addSeconds($ttl)->timestamp;
		Redis::zadd("user_tokens:{$uuid}", $expiresAt, $token);
    }

    /**
     * Remove a JWT token from Redis for a given user UUID.
     *
     * This method deletes the token details, the mapping from token to user,
     * and removes the token from the sorted set of user tokens.
     *
     * @param string $uuid The user UUID
     * @param string $token The JWT token
     * @return void
     */

	public function removeTokenFromRedis($uuid, $token)
	{
		// Hapus detail token
		Redis::del("token_details:{$token}");
		
		// Hapus mapping token ke user
		Redis::del("token_to_user:{$token}");
		
		// Hapus token dari sorted set user
		Redis::zrem("user_tokens:{$uuid}", $token);
	}

    /**
     * Clean expired tokens for a given user UUID.
     *
     * This method uses the user_tokens:{$uuid} sorted set to remove all tokens
     * with a score (expiration time) less than the current timestamp.
     *
     * @param string $uuid The user UUID
     * @return void
     */
	public function cleanExpiredTokens($uuid)
	{
		$now = now()->timestamp;
		// Hapus semua token dengan score < timestamp sekarang (sudah expired)
		Redis::zremrangebyscore("user_tokens:{$uuid}", '-inf', $now - 1);
	}
}