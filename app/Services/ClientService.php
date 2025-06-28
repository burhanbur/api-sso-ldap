<?php 

namespace App\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Models\Application;
use App\Models\User;
use App\Models\UserRole;
use App\Http\Resources\UserResource;
use App\Utilities\Ldap;
use App\Utilities\Utils;
use App\Traits\ApiResponse;

use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;

use Exception;

class ClientService
{
    public function validateTokenClient($user, $tokenString, $appId)
    {
        $response = ['success' => false, 'message' => null, 'data' => []];

        $now = now()->timestamp;
        // Check if token exists in Redis and is still valid
        $expiryTime = Redis::zscore("user_tokens:{$user->uuid}", $tokenString);
        if (!$expiryTime || $expiryTime < $now) {
            return [
                'success' => false,
                'message' => 'Token yang digunakan tidak berlaku atau sudah habis masa berlakunya.',
                'data' => []
            ];
        }

        // Load user relationships needed by client applications
        $user->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType']);

        // Check if user has access to the requesting application
        $hasAccess = $user->userRoles()
            ->whereHas('application', function ($query) use ($appId) {
                $query->where('uuid', $appId)
                        ->where('is_active', true);
            })
            ->exists();

        if (!$hasAccess) {
            return [
                'success' => false,
                'message' => 'Akses ke aplikasi ini tidak diizinkan untuk pengguna ini.',
                'data' => []
            ];
        }

        // Get user roles specific to this application
        $applicationRoles = $user->userRoles()
            ->with(['role', 'entityType'])
            ->whereHas('application', function ($query) use ($appId) {
                $query->where('uuid', $appId);
            })
            ->get();
    
        // Get token details
        $details = Redis::get("token_details:{$tokenString}");
        $isImpersonation = false;
        $impersonatedBy = null;
        
        if ($details) {
            $details = json_decode($details, true);
            if (isset($details['is_impersonation']) && $details['is_impersonation']) {
                $isImpersonation = true;
                $adminUser = User::where('uuid', $details['impersonated_by'])->first();
                $impersonatedBy = $adminUser ? $adminUser->name : 'Unknown Admin';
            }
        }
        
        // Return user information for the client application
        $response = [
            'success' => true,
            'user' => new UserResource($user),
            'access_token' => $tokenString,
            'token_type' => 'bearer',
            'expires_in' => ($expiryTime - $now),
            'formatted_expires_in' => Carbon::createFromTimestamp($expiryTime)->format('Y-m-d H:i:s'),
            'sso_session_valid' => true,
            'application_roles' => $applicationRoles->map(function ($userRole) {
                return [
                    'role' => [
                        'name' => $userRole->role->name,
                        'display_name' => $userRole->role->display_name,
                    ],
                    'entity_type' => $userRole->entityType ? [
                        'name' => $userRole->entityType->name,
                        'code' => $userRole->entityType->code,
                    ] : null,
                    'entity_id' => $userRole->entity_id,
                ];
            })
        ];
        
        if ($isImpersonation) {
            $response['is_impersonation'] = true;
            $response['impersonated_by'] = $impersonatedBy;
        }

        return $response;
    }
}