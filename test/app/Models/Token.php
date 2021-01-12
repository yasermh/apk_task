<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Token extends Model
{
    use HasFactory;

    protected $fillable = [
        'token',
        'phone_number',
        'validity',
        'validity_unit'
    ];

    public function user(){
        return $this->hasone('App\Models\User');
    }
}
