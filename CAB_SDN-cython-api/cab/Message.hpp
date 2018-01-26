#pragma once
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
//This Message class define a message format between CABDaemon Server and Client.
class Message
{
public:
    enum { header_length = 4 };
    enum { max_body_length = 1024*1024};

    Message()
        : body_length_(0), is_header_network_ordered(false)
    {
    }

    const char* data() const
    {
        return data_;
    }

    char* data()
    {
        return data_;
    }

    std::uint32_t length() const
    {
        return header_length + body_length_;
    }

    const char* body() const
    {
        return data_ + header_length;
    }

    char* body()
    {
        return data_ + header_length;
    }

    std::uint32_t body_length() const
    {
        return body_length_;
    }

    void body_length(std::uint32_t new_length)
    {
        body_length_ = new_length;
        if (body_length_ > max_body_length)
            body_length_ = max_body_length;
    }
    
    ///append binary data.
    bool append(char * data, uint32_t length)
    {
        if(body_length_ + length > max_body_length)
        {
            return false;
        }
        memcpy(data + body_length_, data, length);
        body_length_ += length;
        return true;
    }
    ///append unsigned int,automatically convert to network order.
    bool append_uint(uint32_t intger)
    {
        uint32_t net_intger = htonl(intger);
        memcpy(data_ + header_length + body_length_, (char *)&net_intger, 4);
        body_length_ += 4;
        return true;
    }

    ///before sent out, header should be encoded.
    bool decode_header()
    {
        std::memcpy(&body_length_, data_, header_length);
        body_length_ = ntohl(body_length_);

        if (body_length_ > max_body_length)
        {
            body_length_ = 0;
            return false;
        }
        is_header_network_ordered = false;
        return true;
    }

    ///after received, header should be decoded.
    void encode_header()
    {
        std::uint32_t body_length_net = htonl(body_length_);
        std::memcpy(data_, &body_length_net, 4);
        is_header_network_ordered = true;
    }

    void clear()
    {
        body_length_ = 0;
        std::memset(data_,0 ,header_length + max_body_length);
        is_header_network_ordered = false;
    }

private:
    char data_[header_length + max_body_length];
    std::uint32_t body_length_;
    bool is_header_network_ordered;
};
