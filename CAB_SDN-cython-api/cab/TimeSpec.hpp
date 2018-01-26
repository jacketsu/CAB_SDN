#include <time.h>

const unsigned int NSEC_MAX = 1000000000;

class TimeSpec {
public:
    TimeSpec(__time_t tv_sec = 0, int tv_nsec = 0):time_point_ {tv_sec,tv_nsec} {}

    TimeSpec(bool is_real_time) {
        if(is_real_time) {
            clock_gettime(CLOCK_REALTIME,&time_point_);
        } else {
            clock_gettime(CLOCK_MONOTONIC,&time_point_);
        }
    }
    TimeSpec(const timespec & t):time_point_(t) {}
    TimeSpec(const TimeSpec & t):time_point_(t.time_point_) {}
    TimeSpec(double dt) {
        unsigned long us = dt*NSEC_MAX;
        time_point_.tv_sec = us / NSEC_MAX;
        time_point_.tv_nsec = us - time_point_.tv_sec*NSEC_MAX;
    }

    timespec get_timespec()const {
        return time_point_;
    }
    timespec & get_timespec() {
        return time_point_;
    }

    double to_double() {
        double rs = time_point_.tv_sec;
        rs += (double)time_point_.tv_nsec/NSEC_MAX;
        return rs;
    }
    TimeSpec & operator=(const TimeSpec a) {
        time_point_ = a.time_point_;
        return *this;
    }

    bool operator<(const TimeSpec a) {
        if(time_point_.tv_sec != a.time_point_.tv_sec) {
            return time_point_.tv_sec < a.time_point_.tv_sec ? true : false;
        } else {
            return time_point_.tv_nsec < a.time_point_.tv_nsec ? true : false;
        }
    };

    friend TimeSpec operator + (const TimeSpec & a, const TimeSpec &b);
    friend TimeSpec operator - (const TimeSpec & a, const TimeSpec &b);
    timespec time_point_;
};

TimeSpec operator + (const TimeSpec & a, const TimeSpec &b) {
    TimeSpec rs;
    rs.time_point_.tv_sec = a.time_point_.tv_sec + b.time_point_.tv_sec;
    rs.time_point_.tv_nsec = a.time_point_.tv_nsec + b.time_point_.tv_nsec;
    if(rs.time_point_.tv_nsec > NSEC_MAX) {
        rs.time_point_.tv_sec -= 1;
        rs.time_point_.tv_nsec -= NSEC_MAX;
    }
    return rs;
}

TimeSpec operator - (const TimeSpec & a, const TimeSpec &b) {

    TimeSpec rs;
    long nsec = a.time_point_.tv_nsec - b.time_point_.tv_nsec;
    rs.time_point_.tv_sec = a.time_point_.tv_sec - b.time_point_.tv_sec;
    if(nsec < 0) {
        nsec += NSEC_MAX;
        rs.time_point_.tv_sec -=1;
    }
    rs.time_point_.tv_nsec = nsec;
    return rs;
}
