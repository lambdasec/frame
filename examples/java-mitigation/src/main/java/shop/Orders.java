package shop;

import com.alibaba.fastjson.JSON;

public class Orders {
    public static Order parse(String body) {
        return JSON.parseObject(body, Order.class);
    }

    public static class Order {
        public String id;
        public int quantity;
    }
}
