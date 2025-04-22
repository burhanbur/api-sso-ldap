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

use App\Models\RoleType;
use App\Http\Resources\RoleTypeResource;
use App\Traits\ApiResponse;

use Exception;

class RoleTypeController extends Controller
{
    use ApiResponse;

    public function index(Request $request)
    {
        try {
            $data = RoleType::orderBy('id')->paginate(10);

            return $this->successResponse(
                RoleTypeResource::collection($data),
                'Role types retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }
}
