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

use App\Models\EntityType;
use App\Http\Resources\EntityTypeResource;
use App\Traits\ApiResponse;

use Exception;

class EntityTypeController extends Controller
{
    use ApiResponse;

    public function index(Request $request)
    {
        try {
            $data = EntityType::orderBy('id')->paginate(10);

            return $this->successResponse(
                EntityTypeResource::collection($data),
                'Entity types retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }
}
