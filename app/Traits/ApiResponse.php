<?php

namespace App\Traits;

use Illuminate\Http\Resources\Json\ResourceCollection;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Log;

trait ApiResponse
{
    protected function successResponse($data, $message = null, $code = 200)
    {
        $count = 1;
        $pagination = null;

        if ($data instanceof ResourceCollection) {
            if ($data->resource instanceof LengthAwarePaginator) {
                $count = $data->total();
                $pagination = [
                    'total' => $data->total(),
                    'per_page' => $data->perPage(),
                    'current_page' => $data->currentPage(),
                    'last_page' => $data->lastPage(),
                    'from' => $data->firstItem(),
                    'to' => $data->lastItem(),
                ];
            } else {
                $count = $data->count();
            }
        } elseif ($data instanceof JsonResource) {
            $count = 1;
        } elseif (is_array($data)) {
            $count = count($data);
        } elseif (is_null($data)) {
            $count = 0;
        }

        $response = [
            'success' => true,
            'message' => $message,
            'url' => request()->url(),
            'method' => request()->method(),
            'timestamp' => now()->toDateTimeString(),
            'total_data' => $count,
            'data' => $data,
        ];

        if ($pagination) {
            $response['pagination'] = $pagination;
        }

        return response()->json($response, $code);
    }

    protected function errorResponse($message, $code = 400)
    {
        // Jika message berupa array atau JSON string, konversi ke string
        if (is_array($message) || is_object($message)) {
            $message = collect($message)->flatten()->implode(', ');
        } elseif (is_string($message)) {
            // Coba decode dan proses kalau dia berbentuk JSON string
            $decoded = json_decode($message, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $message = collect($decoded)->flatten()->implode(', ');
            }
        }

        if (env('APP_ENV') == 'live') {
            Log::error($message, [
                'url' => request()->url(),
                'method' => request()->method(),
                'timestamp' => now()->toDateTimeString(),
            ]);
            $message = 'An error occurred while processing your request. Please try again later.';
        }

        return response()->json([
            'success' => false,
            'message' => $message,
            'url' => request()->url(),
            'method' => request()->method(),
            'timestamp' => now()->toDateTimeString(),
        ], $code);
    }
}