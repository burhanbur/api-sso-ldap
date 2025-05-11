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

use App\Models\Role;
use App\Http\Resources\RoleResource;
use App\Utilities\Ldap;
use App\Traits\ApiResponse;

use Exception;

class RoleController extends Controller
{
    use ApiResponse;

    public function index(Request $request)
    {
        try {
            $query = Role::with(['roleType', 'scopeType']);

            if ($search = $request->query('search')) {
                $query->where(function($q) use ($search) {
                    $q->where('name', 'ilike', "%{$search}%")
                      ->orWhere('display_name', 'ilike', "%{$search}%")
                      ->orWhere('description', 'ilike', "%{$search}%");
                });
            }

            if ($roleType = $request->query('role_type_id')) {
                $query->where('role_type_id', $roleType);
            }

            if ($scopeType = $request->query('scope_type_id')) {
                $query->where('scope_type_id', $scopeType);
            }

            $sortParams = $request->query('sort');
            if ($sortParams) {
                $sorts = explode(';', $sortParams);
                $allowedSortFields = ['created_at', 'name', 'display_name'];
    
                foreach ($sorts as $sort) {
                    [$field, $direction] = explode(',', $sort) + [null, 'asc'];
                    $direction = strtolower($direction) === 'desc' ? 'desc' : 'asc';
    
                    if (in_array($field, $allowedSortFields)) {
                        $query->orderBy($field, $direction);
                    } else {
                        $query->orderBy('name');
                    }
                }
            } else {
                $query->orderBy('name');
            }

            $data = $query->paginate((int) $request->query('limit', 10));

            return $this->successResponse(
                RoleResource::collection($data),
                'Roles retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:roles',
            'display_name' => 'required|string|max:255',
            'description' => 'nullable|string',
            'role_type_id' => 'nullable|exists:role_types,id',
            'scope_type_id' => 'nullable|exists:scopes,id'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $role = Role::create([
                'uuid' => Str::uuid(),
                'name' => $request->name,
                'display_name' => $request->display_name,
                'description' => $request->description,
                'role_type_id' => $request->role_type_id,
                'scope_type_id' => $request->scope_type_id
            ]);

            DB::commit();

            return $this->successResponse(
                new RoleResource($role->load(['roleType', 'scopeType'])),
                'Role created successfully',
                201
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    public function show($uuid)
    {
        try {
            $role = Role::with(['roleType', 'scopeType'])
                ->where('uuid', $uuid)
                ->first();

            if (!$role) {
                return $this->errorResponse('Role not found', 404);
            }
            
            return $this->successResponse(
                new RoleResource($role),
                'Role retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    public function update(Request $request, $uuid)
    {
        $role = Role::where('uuid', $uuid)->first();

        if (!$role) {
            return $this->errorResponse('Role not found', 404);
        }

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:roles,name,'.$role->id,
            'display_name' => 'required|string|max:255',
            'description' => 'nullable|string',
            'role_type_id' => 'nullable|exists:role_types,id',
            'scope_type_id' => 'nullable|exists:scopes,id'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $role->update([
                'name' => $request->name,
                'display_name' => $request->display_name,
                'description' => $request->description,
                'role_type_id' => $request->role_type_id,
                'scope_type_id' => $request->scope_type_id
            ]);

            DB::commit();

            return $this->successResponse(
                new RoleResource($role->load(['roleType', 'scopeType'])),
                'Role updated successfully'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    public function destroy($uuid)
    {
        try {
            DB::beginTransaction();

            $role = Role::where('uuid', $uuid)->first();

            if (!$role) {
                return $this->errorResponse('Role not found', 404);
            }
            
            // Check if role has any users
            if ($role->users()->exists()) {
                return $this->errorResponse('Cannot delete role with assigned users', 422);
            }

            $role->delete();

            DB::commit();

            return $this->successResponse(
                null,
                'Role deleted successfully'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }
}
