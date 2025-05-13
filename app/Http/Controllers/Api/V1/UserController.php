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

use App\Models\User;
use App\Models\UserRole;
use App\Http\Resources\UserResource;
use App\Utilities\Ldap;
use App\Utilities\Utils;
use App\Traits\ApiResponse;

use Exception;

class UserController extends Controller
{
    use ApiResponse;

    public function index(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        try {
            $query = User::with(['userRoles.role', 'userRoles.application', 'userRoles.entityType']);

            if ($search = $request->query('search')) {
                $query->where(function ($q) use ($search) {
                    $q->where('username', 'ilike', "%$search%")
                      ->orWhere('full_name', 'ilike', "%$search%")
                      ->orWhere('code', 'ilike', "%$search%")
                      ->orWhere('email', 'ilike', "%$search%")
                      ->orWhere('nickname', 'ilike', "%$search%");
                });
            }
    
            if ($status = $request->query('status')) {
                $query->where('status', $status);
            }

            $sortParams = $request->query('sort');
            if ($sortParams) {
                $sorts = explode(';', $sortParams);
                $allowedSortFields = ['created_at', 'full_name', 'code', 'username', 'status'];
    
                foreach ($sorts as $sort) {
                    [$field, $direction] = explode(',', $sort) + [null, 'asc'];
                    $direction = strtolower($direction) === 'desc' ? 'desc' : 'asc';
    
                    if (in_array($field, $allowedSortFields)) {
                        $query->orderBy($field, $direction);
                    } else {
                        $query->orderBy('full_name');
                    }
                }
            } else {
                $query->orderBy('full_name');
            }
    
            $data = $query->paginate((int) $request->query('limit', 10));
            
            $response = $this->successResponse(
                // $users,
                UserResource::collection($data),
                'Users retrieved successfully'
            );
        } catch (Exception $ex) {
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    public function show($uuid)
    {
        $response = $this->errorResponse($this->errMessage);
        
        try {
            $user = User::with(['userRoles.role', 'userRoles.application', 'userRoles.entityType'])->where('uuid', $uuid)->first();

            if (!$user) {
                return $this->errorResponse('User not found', 404);
            }
            
            $response = $this->successResponse(
                new UserResource($user),
                'User retrieved successfully'
            );
        } catch (Exception $ex) {
            $response = $this->errorResponse($ex->getMessage(), 500);
        }
        
        return $response;
    }

    public function store(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255|unique:users',
            'password' => 'required|string|min:8',
            'password_confirmation' => 'required|string|same:password',
            'code' => 'required|string|max:255',
            'full_name' => 'required|string|max:255',
            'nickname' => 'nullable|string|max:255',
            'email' => 'nullable|email',
            'alt_email' => 'nullable|email',
            'join_date' => 'nullable|date',
            'title' => 'nullable|string|max:255',
            'status' => 'nullable|string|in:Aktif,Tidak Aktif',
            'app_access' => 'nullable|array',
            'app_access.*.app_id' => 'required|exists:applications,id',
            'app_access.*.role_id' => 'required|exists:roles,id',
            'app_access.*.entity_type_id' => 'nullable|exists:entity_types,id',
            'app_access.*.entity_id' => 'nullable|string|max:255',
        ], [
            'username.unique' => 'Username already exists',
            'password.min' => 'Password must be at least 8 characters',
            'password_confirmation.same' => 'Password confirmation does not match',
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
            'app_access.array' => 'User roles must be provided as an array',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $plainPassword = $request->password;
            $bcryptPassword = bcrypt($request->password);

            $params = [];
            $params['uuid'] = Str::uuid();
            $params['username'] = $request->username;
            $params['password'] = $bcryptPassword;
            $params['code'] = $request->code;
            $params['full_name'] = $request->full_name;
            $params['nickname'] = $request->nickname ?? $request->full_name;
            $params['email'] = $request->email;
            $params['alt_email'] = $request->alt_email;
            $params['join_date'] = $request->join_date ?? now()->format('Y-m-d');
            $params['title'] = $request->title;
            $params['status'] = $request->status ?? 'Aktif';

            $user = User::create($params);



            $sync = Ldap::syncUserFromLdap($user, 'store', $plainPassword);

            if (!$sync) {
                return $this->errorResponse('Failed to sync user from LDAP', 500);
            }

            DB::commit();
            
            $response = $this->successResponse(
                new UserResource($user),
                'User created successfully'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    public function update(Request $request, $uuid)
    {
        $response = $this->errorResponse($this->errMessage);

        $user = User::where('uuid', $uuid)->first();

        if (!$user) {
            return $this->errorResponse('User not found', 404);
        }

        $validator = Validator::make($request->all(), [
            'username' => "required|string|max:255|unique:users,username,{$user->id}",
            'code' => 'required|string|max:255',
            'full_name' => 'required|string|max:255',
            'nickname' => 'nullable|string|max:255',
            'email' => 'nullable|email',
            'alt_email' => 'nullable|email',
            'join_date' => 'nullable|date',
            'title' => 'nullable|string|max:255',
            'status' => 'nullable|string|in:Aktif,Tidak Aktif',
            'app_access' => 'nullable|array',
            'app_access.*.app_id' => 'required|exists:applications,id',
            'app_access.*.role_id' => 'required|exists:roles,id',
            'app_access.*.entity_type_id' => 'nullable|exists:entity_types,id',
            'app_access.*.entity_id' => 'nullable|string|max:255',
        ], [
            'username.unique' => 'Username already exists',
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
            'app_access.array' => 'User roles must be provided as an array',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = [
                'username' => $request->input('username') ?? $user->username,
                'code' => $request->input('code') ?? $user->code,
                'full_name' => $request->input('full_name') ?? $user->full_name,
                'nickname' => $request->input('nickname') ?? $user->nickname,
                'email' => $request->input('email') ?? $user->email,
                'alt_email' => $request->input('alt_email') ?? $user->alt_email,
                'join_date' => $request->input('join_date') ?? $user->join_date,
                'title' => $request->input('title') ?? $user->title,
                'status' => $request->input('status', 'Aktif') ?? $user->status,
            ];

            $user->update($params);
            $this->_syncUserAccess($request->app_access, $user);
            $sync = Ldap::syncUserFromLdap($user, 'update');

            if (!$sync) {
                return $this->errorResponse('Failed to sync user from LDAP', 500);
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource($user),
                'User updated successfully'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    /**
     * Sync user access (roles) with the given user.
     *
     * @param array $appAccess
     * @param User $user
     * @return void
     */
    private function _syncUserAccess(array $appAccess = [], User $user): void
    {
        $assignedBy = auth()->user()->id;
        $now = date('Y-m-d H:i:s');

        foreach ($appAccess as $key => $value) {
            $access = UserRole::where([
                'user_id' => $user->id, 
                'app_id' => $value->app_id, 
                'role_id' => $value->role_id,
            ])->first();

            if ($access) {
                $access->update([
                    'entity_type_id' => $value->entity_type_id,
                    'entity_id' => $value->entity_id,
                    'assign_by' => $assignedBy,
                    'assign_at' => $now,
                ]);
            } else {
                UserRole::create([
                    'uuid' => Str::uuid(),
                    'user_id' => $user->id,
                    'role_id' => $value->role_id,
                    'app_id' => $value->app_id,
                    'entity_type_id' => $value->entity_type_id,
                    'entity_id' => $value->entity_id,
                    'assign_by' => $assignedBy,
                    'assign_at' => $now,
                ]);
            }
        }
    }

    public function updateStatus(Request $request, $uuid)
    {
        $response = $this->errorResponse($this->errMessage);

        $user = User::where('uuid', $uuid)->first();

        if (!$user) {
            return $this->errorResponse('User not found', 404);
        }

        $validator = Validator::make($request->all(), [
            'status' => 'nullable|string|in:Aktif,Tidak Aktif',
        ], [
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = [
                'status' => $request->input('status', 'Aktif') ?? $user->status,
            ];

            $user->update($params);
            $sync = Ldap::syncUserFromLdap($user, 'update');

            if (!$sync) {
                return $this->errorResponse('Failed to sync user status from LDAP', 500);
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource($user),
                'User status updated successfully'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }
    
    public function generateUsername(Request $request)
    {

    }

    public function userLdap()
    {
        // if (!$ldapConnection = Ldap::connectToLdap()) {
        //     return null;
        // }

        // $dn = "uid=lmawati," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
        // @ldap_delete($ldapConnection, $dn);

        return $this->successResponse(
            Ldap::listLdapUsers(),
            'User data retrieved successfully'
        );
    }
}
