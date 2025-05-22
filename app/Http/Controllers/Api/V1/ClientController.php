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
                return $this->errorResponse('Code is required', 400);
            }

            $user = User::where('code', $code)->first();

            if (!$user) {
                return $this->errorResponse('User not found', 404);
            }

            return $this->successResponse(
                new UserResource($user), 
                'User retrieved successfully'
            );
        } catch (Exception $e) {
            Log::error('Error retrieving user by code: ' . $e->getMessage());
            return $this->errorResponse('An error occurred while retrieving the user', 500);
        }
    }    public function insertOrUpdateUser(Request $request)
    {
        try {
            DB::beginTransaction();

            $validator = Validator::make($request->all(), [
                'code' => 'required|string|max:255',
                'name' => 'required|string|max:255',
                'username' => 'required|string|max:255',
                'email' => 'required|email|max:255',
                'password' => 'required|string|min:8|confirmed',
                'app_code' => 'required|string|exists:applications,code',
                'roles' => 'required|array',
                'roles.*.code' => 'required|string|exists:roles,name',
                'roles.*.entity' => 'nullable|array',
                'roles.*.entity.type' => 'nullable|string|exists:entity_types,code',
                'roles.*.entity.id' => 'nullable|string|max:50'
            ]);

            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 422);
            }

            // Find application by code
            $application = Application::where('code', $request->app_code)->first();
            if (!$application) {
                return $this->errorResponse('Application not found', 404);
            }

            // Find or create user
            $user = User::where('code', $request->code)->first();
            $isNewUser = !$user;

            if ($isNewUser) {
                $user = new User();
                $user->uuid = Str::uuid();
                $user->password = bcrypt($request->password);
            }

            // Update user data
            $user->code = $request->code;
            $user->username = $request->username;
            $user->full_name = $request->name;
            $user->nickname = $request->input('nickname', $request->name);
            $user->email = $request->email;
            $user->alt_email = $request->input('alt_email');
            $user->join_date = $request->input('join_date', now()->format('Y-m-d'));
            $user->title = $request->input('title');
            $user->status = $request->input('status', 'Aktif');

            // Save user
            $user->save();

            // Prepare roles data
            $appAccess = [];
            foreach ($request->roles as $roleData) {
                $role = Role::where('name', $roleData['code'])->first();
                if (!$role) {
                    continue;
                }

                $entityTypeId = null;
                $entityId = null;
                if (!empty($roleData['entity'])) {
                    $entityType = EntityType::where('code', $roleData['entity']['type'])->first();
                    if ($entityType) {
                        $entityTypeId = $entityType->id;
                        $entityId = $roleData['entity']['id'];
                    }
                }

                $appAccess[] = [
                    'app_id' => $application->id,
                    'role_id' => $role->id,
                    'entity_type_id' => $entityTypeId,
                    'entity_id' => $entityId
                ];
            }

            // Sync user roles
            $this->_syncUserAccess($user, $appAccess);

            // Sync with LDAP
            if ($isNewUser) {
                $sync = Ldap::syncUserFromLdap($user, 'store', $request->password);
            } else {
                $sync = Ldap::syncUserFromLdap($user, 'update');
            }

            if (!$sync) {
                DB::rollBack();
                return $this->errorResponse('Failed to sync user with LDAP', 500);
            }

            DB::commit();

            return $this->successResponse(
                new UserResource($user->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType'])), 
                'User ' . ($isNewUser ? 'created' : 'updated') . ' successfully'
            );
        } catch (Exception $e) {
            DB::rollBack();
            Log::error('Error creating/updating user: ' . $e->getMessage());
            return $this->errorResponse('An error occurred while creating or updating the user', 500);
        }
    }

    /**
     * Sync user access (roles) with the given user.
     *
     * @param User $user
     * @param array $appAccess
     * @return void
     */
    private function _syncUserAccess(User $user, array $appAccess = []): void
    {
        $assignedBy = auth()->user()->id;
        $now = now();

        $existingAccess = UserRole::where('user_id', $user->id)->get();
        $incomingKeys = [];

        foreach ($appAccess as $value) {
            $key = $value['app_id'] . '-' . $value['role_id'];
            $incomingKeys[] = $key;

            $access = $existingAccess->firstWhere(function ($item) use ($value) {
                return $item->app_id == $value['app_id'] && $item->role_id == $value['role_id'];
            });

            if ($access) {
                $access->update([
                    'entity_type_id' => $value['entity_type_id'],
                    'entity_id' => $value['entity_id'],
                    'assigned_by' => $assignedBy,
                    'assigned_at' => $now,
                ]);
            } else {
                UserRole::create([
                    'uuid' => Str::uuid(),
                    'user_id' => $user->id,
                    'role_id' => $value['role_id'],
                    'app_id' => $value['app_id'],
                    'entity_type_id' => $value['entity_type_id'],
                    'entity_id' => $value['entity_id'],
                    'assigned_by' => $assignedBy,
                    'assigned_at' => $now,
                ]);
            }
        }

        foreach ($existingAccess as $oldAccess) {
            $key = $oldAccess->app_id . '-' . $oldAccess->role_id;
            if (!in_array($key, $incomingKeys)) {
                $oldAccess->delete();
            }
        }
    }

}