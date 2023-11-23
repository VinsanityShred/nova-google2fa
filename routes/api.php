<?php

use Illuminate\Support\Facades\Route;

/**
 * This route is called when user must first time confirm secret
 */
Route::post('register', 'VinsanityShred\Google2fa\Google2fa@register');

/**
 * This route is called when user must first time confirm secret
 */
Route::post('confirm', 'VinsanityShred\Google2fa\Google2fa@confirm');

/**
 * This route is called to verify users secret
 */
Route::post('authenticate', 'VinsanityShred\Google2fa\Google2fa@authenticate');
