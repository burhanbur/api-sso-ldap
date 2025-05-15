<?php

namespace App\Imports;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;

use Maatwebsite\Excel\Concerns\ToArray;
use Maatwebsite\Excel\Concerns\WithStartRow;

class ReadExcelImport implements ToArray, WithStartRow
{
	/**
     * @return int
     */
    public function startRow(): int
    {
        return 2;
    }
    
	public function array(array $rows)
	{
		return $rows; 
	}
}