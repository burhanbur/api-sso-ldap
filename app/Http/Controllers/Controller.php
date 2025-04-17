<?php

namespace App\Http\Controllers;

abstract class Controller
{
    public $errMessage = 'Internal Server Error';
    public $errCode = 500;
}
