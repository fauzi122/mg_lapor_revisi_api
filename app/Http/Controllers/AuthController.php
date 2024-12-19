<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function login_sso(Request $request)
    {
        //dd($this->cas_url());
        $sso_redirect_path = env('URL_LOGIN_SSO', url('login_sso'));

        if ($request->has('ticket')) {
            list($verified, $data, $error) = $this->verifySSOTicket($request->get('ticket'));

            //proses otentikasi
            if ($verified) {
                // Proses jika otentikasi berhasil
                return response()->json(['status' => 'success', 'data' => $data]);
            } else {
                // Proses jika otentikasi gagal
                return response()->json(['status' => 'error', 'message' => $error]);
            }
        } else {
            // Redirect ke SSO jika tidak ada tiket
            return redirect($this->cas_url().'/login?service='.urlencode($sso_redirect_path));
        }
    }

    private function verifySSOTicket($ticket)
    {
        $sso_redirect_path = env('URL_LOGIN_SSO', url('login_sso'));
        $success = false;
        $data = [];
        $error = null;

        $url = $this->cas_url() . "/p3/serviceValidate?format=json&service=" . $sso_redirect_path . "&ticket=" . $ticket;

        $arrContextOptions = [
            "ssl" => [
                "verify_peer" => false,
                "verify_peer_name" => false,
            ]
        ];
        $resp = json_decode(file_get_contents($url, false, stream_context_create($arrContextOptions)));

        if ($resp) {
            if($resp->serviceResponse){
                if (isset($resp->serviceResponse->authenticationFailure)) {
                    $error = $resp->serviceResponse->authenticationFailure->description;
                } elseif (isset($resp->serviceResponse->authenticationSuccess)) {
                    $success = true;
                    $data = $resp->serviceResponse->authenticationSuccess->attributes ?? (object)[];
                    $data->username = $resp->serviceResponse->authenticationSuccess->user;
                } else {
                    $error = "Not a valid CAS Response";
                }
            }
            else{
                $error = "Not a valid CAS Response";
            }
        } else {
            $error = "Failed to connect to SSO server";
        }

        return [$success, $data, $error];
    }

    private function cas_url()
    {
        return env('CAS_BASE_URL', 'https://auth.esdm.go.id/cas');
    }
}
