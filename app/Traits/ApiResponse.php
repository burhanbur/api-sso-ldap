<?php

namespace App\Traits;

trait ApiResponse
{
    protected function successResponse($data, $message = null, $code = 200)
    {
        return response()->json([
            'success' => true,
            'message' => $message,
            'url' => request()->url(),
            'method' => request()->method(),
            'timestamp' => now()->toDateTimeString(),
            'data' => $data,
        ], $code);
    }

    protected function errorResponse($message, $code = 400)
    {
        return response()->json([
            'success' => false,
            'message' => $message,
            'url' => request()->url(),
            'method' => request()->method(),
            'timestamp' => now()->toDateTimeString(),
        ], $code);
    }
}