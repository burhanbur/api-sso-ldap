<?php

use Illuminate\Support\Facades\Route;

require __DIR__.'/oauth.php';

Route::get('/', function () {
    return view('welcome');
});