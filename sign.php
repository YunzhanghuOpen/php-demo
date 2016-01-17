<?php

date_default_timezone_set('Asia/Chongqing');

$partner = '';                       // 商户编号（测试环境）
$key = '';                           // 签名秘钥（测试环境）
$baseUrl = '';                       // 接口地址（测试环境）


$runtime = time();
echo sprintf("date : %s \n", date('Y-m-d H:i:s', $runtime));

$input = [
    'mobile' => 18612341234,
    'partner' => $partner,
    'user_id' => 1017,
    'timestamp' => $runtime,
];

// 签名示范
$sign = HMAC::calculate($input, $key);
echo sprintf("sign : %s\n", $sign);

$queryData = array_merge($input, ['sign' => $sign]);
$queryString = http_build_query($queryData);

// 固定入口 URL 示范，其他接口类似
$fullUrl = $baseUrl . '/autoLogin?' .  $queryString;
echo sprintf("fullUrl : %s\n", $fullUrl);

// 验签示范
if (HMAC::checkExpired($queryData['timestamp'])) {
    echo sprintf("链接已过期\n", $fullUrl);
    exit;
}
$result = HMAC::compare($queryData, $key, $sign);
echo sprintf("compare result : %s\n", intval($result));
echo "DONE\n";


class HMAC
{

    const TIME_SCOPE = 300; //second 5*60=300

    /**
     * 计算签名
     * @param $input
     * @param $key
     * @return string
     */
    public static function calculate($input, $key)
    {

        $signPars = "";
        ksort($input);
        foreach ($input as $k => $v) {
            $v = strval($v);
            if ("sign" != $k && "" != $v) {
                $signPars .= $k . "=" . $v . "&";
            }
        }
        $signPars .= "key=" . $key;

        // todo Add log
        echo sprintf("original string : %s \n", $signPars);

        $hash = strtolower(hash('sha256', $signPars));

        // todo Add log
        echo sprintf("hash : %s \n", $hash);

        return $hash;
    }

    /**
     * 比较签名
     * @param $input
     * @param $key
     * @param $sign
     * @return bool
     */
    public static function compare($input, $key, $sign)
    {

        $hash = self::calculate($input, $key);

        $rst = $hash === $sign;

        // todo Add log
        echo sprintf("result : %s \n", intval($rst));

        return $rst;
    }

    /**
     * 检查授权链接是否过期
     * @param $timestamp
     * @return bool
     */
    static function checkExpired($timestamp)
    {
        $offset = abs(time() - $timestamp);
        return $offset > self::TIME_SCOPE;
    }


}
