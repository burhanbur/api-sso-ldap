<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Web\V1\AuthController;

Route::get('/', function () {
    return view('welcome');
});

Route::post('/redirect', [AuthController::class, 'redirectLogin']);