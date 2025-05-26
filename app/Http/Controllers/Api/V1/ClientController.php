<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Models\Application;
use App\Models\User;
use App\Models\Role;
use App\Models\UserRole;
use App\Models\EntityType;
use App\Http\Resources\ApplicationResource;
use App\Http\Resources\UserResource;
use App\Utilities\Ldap;
use App\Utilities\Utils;
use App\Traits\ApiResponse;
use App\Imports\ReadExcelImport;

use Maatwebsite\Excel\Facades\Excel;

use Exception;

class ClientController extends Controller
{
    use ApiResponse;

    public function getUserByCode(Request $request)
    {
        try {
            $code = $request->get('code');

            if (!$code) {
                return $this->errorResponse('NIP/NIM wajib diisi.', 400);
            }

            $user = User::where('code', $code)->first();

            if (!$user) {
                return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
            }

            return $this->successResponse(
                new UserResource($user), 
                'User retrieved successfully'
            );
        } catch (Exception $e) {
            Log::error('Error retrieving user by code: ' . $e->getMessage());
            return $this->errorResponse('Terjadi kesalahan saat mengambil pengguna.', 500);
        }
    }    
    
    public function insertOrUpdateUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:255',
            'name' => 'required|string|max:255',
            'type' => 'required|string|max:255|in:student,staff',
            'username' => 'nullable|string|max:255',
            'email' => 'required|email|max:255',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $appId = $request->header('x-app-id');

            // Find application by appId
            $application = Application::where('uuid', $appId)->first();
            if (!$application) {
                return $this->errorResponse('ID aplikasi wajib diisi.', 404);
            }

            // Find or create user
            $user = User::where('code', $request->code)->first();
            $isNewUser = !$user;

            $plainPassword = $request->password;
            $bcryptPassword = bcrypt($request->password);

            if ($isNewUser) {
                $user = new User();
                $user->uuid = Str::uuid();
                $user->code = $request->code;
                $user->password = $bcryptPassword;
                $user->created_by = auth()->user()->id;

                if ($request->username) {
                    $checkUsername = User::where('username', $request->username)->first();

                    if ($checkUsername) {
                        $username = Utils::getInstance()->generateUsername($request->name, $request->type);
                    } else {
                        $username = $request->username;
                    }
                } else {
                    $username = Utils::getInstance()->generateUsername($request->name, $request->type);
                }

                $user->username = $username;
                $user->full_name = $request->name;
                $user->nickname = $request->input('nickname', $request->name);
                $user->email = $request->email;
                $user->alt_email = $request->input('alt_email');
                $user->join_date = $request->input('join_date', now()->format('Y-m-d'));
                $user->title = $request->input('title');
                $user->status = $request->input('status', 'Aktif');
            }
            
            $user->save();

            // Prepare roles data
            $userRole = UserRole::where('user_id', $user->id)
                ->where('app_id', $application->id)
                ->first();
            
            if (!$userRole) {
                $userRole = new UserRole();
                $userRole->uuid = Str::uuid();
                $userRole->user_id = $user->id;
                $userRole->role_id = 2; // Defult role for user
                $userRole->app_id = $application->id;
                $userRole->entity_type_id = null;
                $userRole->entity_id = null;
                $userRole->assigned_by = auth()->user()->id;
                $userRole->assigned_at = now();
                $userRole->save();
            }

            // Sync with LDAP
            if ($isNewUser) {
                $sync = Ldap::syncUserFromLdap($user, 'store', $plainPassword);
            } else {
                $sync = Ldap::syncUserFromLdap($user, 'update');
            }

            if (!$sync) {
                DB::rollBack();
                return $this->errorResponse('Proses sinkronisasi pengguna ke LDAP tidak berhasil.', 500);
            }

            DB::commit();

            return $this->successResponse(
                new UserResource($user->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType'])), 
                'Berhasil ' . ($isNewUser ? 'membuat' : 'mengubah') . ' data pengguna ' . $user->full_name . '.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            Log::error('Error creating/updating user: ' . $e->getMessage());
            return $this->errorResponse('Terjadi kesalahan saat membuat atau memperbarui pengguna.', 500);
        }
    }

}