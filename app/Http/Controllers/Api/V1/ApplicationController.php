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
use App\Models\UserRole;
use App\Http\Resources\ApplicationResource;
use App\Http\Resources\UserAppResource;
use App\Traits\ApiResponse;

use Exception;

class ApplicationController extends Controller
{
    use ApiResponse;

    public function index(Request $request)
    {
        try {
            $query = Application::query();

            // Search functionality
            if ($search = $request->query('search')) {
                $query->where(function($q) use ($search) {
                    $q->where('name', 'ilike', "%{$search}%")
                      ->orWhere('code', 'ilike', "%{$search}%")
                      ->orWhere('alias', 'ilike', "%{$search}%");
                });
            }

            // Filter by platform type
            if ($platformType = $request->query('platform_type')) {
                $query->where('platform_type', $platformType);
            }

            // Filter by status
            if ($status = $request->query('is_active') == 1 ? true : false) {
                $query->where('is_active', $status);
            }

            $sortParams = $request->query('sort');
            if ($sortParams) {
                $sorts = explode(';', $sortParams);
                $allowedSortFields = ['created_at', 'name', 'code', 'alias', 'is_active', 'platform_type'];
    
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
                ApplicationResource::collection($data),
                'Applications retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:50|unique:applications',
            'name' => 'required|string|max:255',
            'alias' => 'nullable|string|max:50',
            'description' => 'nullable|string',
            'base_url' => 'required|url',
            'login_url' => 'required|url',
            'platform_type' => 'required|string|in:Web,Mobile,Desktop',
            'visibility' => 'required|string|in:Public,Internal',
            // 'image' => 'nullable|image|mimes:jpg,jpeg,png|max:2048'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = $validator->validated();
            $params['uuid'] = Str::uuid();
            $params['code'] = strtolower($params['code']);

            // Handle image upload
            if ($request->hasFile('image')) {
                $file = $request->file('image');
                $filename = Str::slug($params['code']) . '.' . $file->getClientOriginalExtension();
                $path = $file->storeAs('public/applications', $filename);
                $params['image'] = Storage::url($path);
            }

            $application = Application::create($params);

            DB::commit();

            return $this->successResponse(
                new ApplicationResource($application),
                'Application created successfully',
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
            $application = Application::where('uuid', $uuid)->first();

            if (!$application) {
                return $this->errorResponse('Application not found', 404);
            }
            
            return $this->successResponse(
                new ApplicationResource($application),
                'Application retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    public function update(Request $request, $uuid)
    {
        $application = Application::where('uuid', $uuid)->first();

        if (!$application) {
            return $this->errorResponse('Application not found', 404);
        }

        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:50|unique:applications,code,'.$application->id,
            'name' => 'required|string|max:255',
            'alias' => 'nullable|string|max:50',
            'description' => 'nullable|string',
            'base_url' => 'required|url',
            'login_url' => 'required|url',
            'platform_type' => 'required|string|in:Web,Mobile,Desktop',
            'visibility' => 'required|string|in:Public,Internal',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = $validator->validated();
            $params['code'] = strtolower($params['code']);

            // Handle image upload
            if ($request->hasFile('image')) {
                // Delete old image
                if ($application->image) {
                    Storage::delete(str_replace('/storage', 'public', $application->image));
                }

                $file = $request->file('image');
                $filename = Str::slug($params['code']) . '.' . $file->getClientOriginalExtension();
                $path = $file->storeAs('public/applications', $filename);
                $params['image'] = Storage::url($path);
            }

            $application->update($params);

            DB::commit();

            return $this->successResponse(
                new ApplicationResource($application),
                'Application updated successfully'
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

            $application = Application::where('uuid', $uuid)->first();

            if (!$application) {
                return $this->errorResponse('Application not found', 404);
            }
            
            // Check if application has any user roles
            if ($application->userRoles()->exists()) {
                return $this->errorResponse('Cannot delete application with assigned user roles', 422);
            }

            // Delete image if exists
            if ($application->image) {
                Storage::delete(str_replace('/storage', 'public', $application->image));
            }

            $application->delete();

            DB::commit();

            return $this->successResponse(
                null,
                'Application deleted successfully'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    public function updateStatus(Request $request, $uuid)
    {
        try {
            DB::beginTransaction();

            $application = Application::where('uuid', $uuid)->first();

            if (!$application) {
                return $this->errorResponse('Application not found', 404);
            }
            
            $application->update(['is_active' => !$application->is_active]);

            DB::commit();

            return $this->successResponse(
                new ApplicationResource($application),
                'Application status updated successfully'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    public function showUserApplication(Request $request, $uuid)
    {
        try {
            $query = UserRole::distinct()
                ->select('user_roles.id', 'users.code', 'users.full_name', 'users.username', 'roles.display_name as role', 'user_roles.uuid', 'user_roles.assigned_at', 'user_roles.assigned_by', 'user_roles.created_at', 'user_roles.updated_at')
                ->join('users', 'users.id', '=', 'user_roles.user_id')
                ->join('applications', 'applications.id', '=', 'user_roles.app_id')
                ->join('roles', 'roles.id', '=', 'user_roles.role_id')
                ->where('applications.uuid', $uuid);

            if ($search = $request->query('search')) {
                $query->where(function ($q) use ($search) {
                    $q->where('users.username', 'ilike', "%$search%")
                      ->orWhere('users.full_name', 'ilike', "%$search%")
                      ->orWhere('users.code', 'ilike', "%$search%")
                      ->orWhere('roles.display_name', 'ilike', "%$search%");
                });
            }
            
            $data = $query->orderBy('users.full_name', 'asc')->orderBy('roles.display_name', 'asc')->get();

            return $this->successResponse(
                UserAppResource::collection($data),
                'User applications retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    public function myApplication(Request $request) 
    {
        $user = auth()->user();

        try {
            $query = Application::distinct()
                ->select('applications.*')
                ->join('user_roles', 'applications.id', '=', 'user_roles.app_id')
                ->join('users', 'users.id', '=', 'user_roles.user_id')
                ->join('roles', 'roles.id', '=', 'user_roles.role_id')
                ->where('applications.is_active', true)
                ->where('applications.code' , '!=', 'sso')
                ->where('applications.code' , '!=', 'SSO')
                ->where('user_roles.user_id', $user->id);
            
            $data = $query->orderBy('applications.name', 'asc')->get();

            return $this->successResponse(
                ApplicationResource::collection($data),
                'My applications retrieved successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }
}
