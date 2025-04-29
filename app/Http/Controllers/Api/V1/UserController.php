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
use App\Http\Resources\UserResource;
use App\Utilities\Ldap;
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
                $allowedSortFields = ['created_at', 'full_name', 'username', 'status'];
    
                foreach ($sorts as $sort) {
                    [$field, $direction] = explode(',', $sort) + [null, 'asc'];
                    $direction = strtolower($direction) === 'desc' ? 'desc' : 'asc';
    
                    if (in_array($field, $allowedSortFields)) {
                        $query->orderBy($field, $direction);
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
        ], [
            'username.unique' => 'Username already exists',
            'password.min' => 'Password must be at least 8 characters',
            'password_confirmation.same' => 'Password confirmation does not match',
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = $validator->validated();
            $params['uuid'] = Str::uuid();
            $params['status'] = $params['status'] ?? 'Aktif';
            $params['join_date'] = $params['join_date'] ?? now()->format('Y-m-d');
            $params['nickname'] = $params['nickname'] ?? $params['full_name'];

            $plainPassword = $params['password'];
            $bcryptPassword = bcrypt($params['password']);
            $params['password'] = $bcryptPassword;

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
        ], [
            'username.unique' => 'Username already exists',
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
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
