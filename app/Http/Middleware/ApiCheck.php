<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ApiCheck
{
    private  $_map = [
        # appkey => appsecret
        '1903' => '1903a'
    ];
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        # 对接口的数据进行解密，并且进新验签操作
//        var_dump($request->all());exit;
        # 解密客户端传递的数据
        $api_request = $this -> _RsaDcrypt($request);

        # 验证签名 【 防止在传输的过程中的数据被篡改 】
        $check_result = $this-> _checkSign( $api_request, $request->post('sign'));

        if( $check_result['status'] != 200){
            return $check_result;
        }else{
            if (!empty($api_request)){
                $request-> replace($api_request);
            }
            return $next($request);
        }
    }

    /**
     * 对接收到的数据使用私钥解密
     */
    private  function _RsaDcrypt(Request $request)
    {
        $data_str = $request->post('data');

        # 私钥解密过程
            # 1. base64 反编码得到的加密串
            # 2. 获取 128 个长度,得到第一个的 加密的结果
            # 3. while循环 加密的数据 进行 拼接

        $all_decrypt = base64_decode( $data_str );
        $j = 0;
        $all_new = '';

        while ( $substr_str = substr($all_decrypt, $j , 128)) {
            openssl_private_decrypt(
                $substr_str,
                $decrypt,
                file_get_contents(public_path().'/ssl/private.key'),
                OPENSSL_PKCS1_PADDING
            );
            $all_new .= $decrypt;
            $j += 128;
        }

        return json_decode($all_new,true);
    }

    /**
     * 对客户端传递的数据进行验签操作
     */
    private function  _checkSign($data,$client_sign)
    {
        if (empty($data)){
            return [
                'status'=>200,
                'data' => [],
                'msg' => 'success'
            ];
        }
        /*
         * 服务端接受数据，对数据进行验签操作
				（1）接受到传递的原始数据
				（2）对数据进行排序操作
				（3）把排序号的数据，转成json格式
				（4）服务端根据客户端传递的 appkey 找到对应的appsecert
				（5）把json拼接上appsecert
				（6）生成一个服务端的签名
				（7）对比服务端和客户端的签名是否一致，如果一致说明数据是没有被篡改的
				（8）如果签名不一致说明数据被篡改了，提示验签失败即可。
        */
        // 对数据进行排序操作 并排序的数据，转化成json格式
        ksort($data);
        $json_str = json_encode($data);

        // 服务端根据客户端传递的 appkey 找到对应的 appsecert
        $secret = $this -> getAppSecretByAppkey($data['app_key']);

        if ($secret['status'] != 200){
            return $secret;
        }else{
            $app_secret = $secret['data']['secret'];
        }

        #把json拼接上appsecert
        $json_str .= '&app_secret='.$app_secret;

        #生成一个服务端的签名
        $server_sign = md5( $json_str );

        # 比较服务端和客户端的签名
        if ($server_sign != $client_sign){
            return ['status'=>1000,'data'=>[],'msg'=> '签名错误'];
        }else{
            return [
                'status'=>200,
                'data' => [],
                'msg' => 'success'
            ];
        }
    }

    /*
     *  通过appid 获取对应的app秘钥
     */

    public function getAppSecretByAppkey($app_key)
    {

        # 如果appid是错误的，直接返回错误信息
        if (!isset( $this -> _map[$app_key])){
            return ['status'=>1000,'data'=>[],'msg'=>'app_key error'];
        }

        return [
            'status' => 200,
            'data' => [
                'secret' => $this -> _map[$app_key]
            ],
            'msg' => 'success'
        ];
    }



}
