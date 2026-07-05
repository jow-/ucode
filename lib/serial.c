#define _DEFAULT_SOURCE

#include <errno.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "ucode/module.h"

#ifndef TIOCINQ
#define TIOCINQ FIONREAD
#endif

#define err_return(err) do { \
	uc_vm_registry_set(vm, "serial.last_error", ucv_int64_new(err)); \
	return NULL; \
} while(0)

static int
get_fd(uc_vm_t *vm, uc_value_t *val)
{
	uc_value_t *fn = ucv_property_get(val, "fileno");
	int64_t n;

	errno = 0;

	if (ucv_is_callable(fn)) {
		uc_vm_stack_push(vm, ucv_get(val));
		uc_vm_stack_push(vm, ucv_get(fn));

		if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
			return -1;

		val = uc_vm_stack_pop(vm);
		n = ucv_int64_get(val);
		ucv_put(val);
	}
	else {
		n = ucv_int64_get(val);
	}

	if (errno || n < 0 || n > (int64_t)INT_MAX)
		return -1;

	return (int)n;
}

static uc_value_t *
uc_serial_error(uc_vm_t *vm, size_t nargs)
{
	int last_error = ucv_int64_get(uc_vm_registry_get(vm, "serial.last_error"));

	if (last_error == 0)
		return NULL;

	uc_vm_registry_set(vm, "serial.last_error", ucv_int64_new(0));

	return ucv_string_new(strerror(last_error));
}

static uc_value_t *
uc_serial_isatty(uc_vm_t *vm, size_t nargs)
{
	int fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	return ucv_boolean_new(isatty(fd) == 1);
}

static uc_value_t *
uc_serial_attr(uc_vm_t *vm, size_t nargs)
{
	struct termios t;
	uc_value_t *rv, *cc;
	int fd, i;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (tcgetattr(fd, &t) != 0)
		err_return(errno);

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "iflag", ucv_uint64_new(t.c_iflag));
	ucv_object_add(rv, "oflag", ucv_uint64_new(t.c_oflag));
	ucv_object_add(rv, "cflag", ucv_uint64_new(t.c_cflag));
	ucv_object_add(rv, "lflag", ucv_uint64_new(t.c_lflag));
	ucv_object_add(rv, "ispeed", ucv_uint64_new(cfgetispeed(&t)));
	ucv_object_add(rv, "ospeed", ucv_uint64_new(cfgetospeed(&t)));

	cc = ucv_array_new(vm);

	for (i = 0; i < NCCS; i++)
		ucv_array_push(cc, ucv_uint64_new(t.c_cc[i]));

	ucv_object_add(rv, "cc", cc);

	return rv;
}

static uc_value_t *
uc_serial_setattr(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *attrs = uc_fn_arg(1);
	uc_value_t *when = uc_fn_arg(2);
	uc_value_t *v, *cc;
	struct termios t;
	int fd, act;
	size_t i, n;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ucv_type(attrs) != UC_OBJECT)
		err_return(EINVAL);

	if (tcgetattr(fd, &t) != 0)
		err_return(errno);

	v = ucv_object_get(attrs, "iflag", NULL);
	if (v) t.c_iflag = (tcflag_t)ucv_to_unsigned(v);

	v = ucv_object_get(attrs, "oflag", NULL);
	if (v) t.c_oflag = (tcflag_t)ucv_to_unsigned(v);

	v = ucv_object_get(attrs, "cflag", NULL);
	if (v) t.c_cflag = (tcflag_t)ucv_to_unsigned(v);

	v = ucv_object_get(attrs, "lflag", NULL);
	if (v) t.c_lflag = (tcflag_t)ucv_to_unsigned(v);

	v = ucv_object_get(attrs, "ispeed", NULL);
	if (v) cfsetispeed(&t, (speed_t)ucv_to_unsigned(v));

	v = ucv_object_get(attrs, "ospeed", NULL);
	if (v) cfsetospeed(&t, (speed_t)ucv_to_unsigned(v));

	cc = ucv_object_get(attrs, "cc", NULL);

	if (ucv_type(cc) == UC_ARRAY) {
		n = ucv_array_length(cc);

		for (i = 0; i < n && i < NCCS; i++) {
			v = ucv_array_get(cc, i);
			if (v) t.c_cc[i] = (cc_t)ucv_to_unsigned(v);
		}
	}

	act = (ucv_type(when) == UC_INTEGER) ? (int)ucv_int64_get(when) : TCSANOW;

	if (tcsetattr(fd, act, &t) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_setspeed(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *speed = uc_fn_arg(1);
	uc_value_t *when = uc_fn_arg(2);
	struct termios t;
	speed_t spd;
	int fd, act;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ucv_type(speed) != UC_INTEGER)
		err_return(EINVAL);

	spd = (speed_t)ucv_to_unsigned(speed);

	if (tcgetattr(fd, &t) != 0)
		err_return(errno);

	if (cfsetispeed(&t, spd) != 0 || cfsetospeed(&t, spd) != 0)
		err_return(errno);

	act = (ucv_type(when) == UC_INTEGER) ? (int)ucv_int64_get(when) : TCSANOW;

	if (tcsetattr(fd, act, &t) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_setraw(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *when = uc_fn_arg(1);
	struct termios t;
	int fd, act;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (tcgetattr(fd, &t) != 0)
		err_return(errno);

	cfmakeraw(&t);

	act = (ucv_type(when) == UC_INTEGER) ? (int)ucv_int64_get(when) : TCSANOW;

	if (tcsetattr(fd, act, &t) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_setblocking(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *vmin = uc_fn_arg(1);
	uc_value_t *vtime = uc_fn_arg(2);
	uc_value_t *when = uc_fn_arg(3);
	struct termios t;
	int fd, act;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ucv_type(vmin) != UC_INTEGER || ucv_type(vtime) != UC_INTEGER)
		err_return(EINVAL);

	if (tcgetattr(fd, &t) != 0)
		err_return(errno);

	t.c_cc[VMIN] = (cc_t)ucv_to_unsigned(vmin);
	t.c_cc[VTIME] = (cc_t)ucv_to_unsigned(vtime);

	act = (ucv_type(when) == UC_INTEGER) ? (int)ucv_int64_get(when) : TCSANOW;

	if (tcsetattr(fd, act, &t) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_mget(uc_vm_t *vm, size_t nargs)
{
	int fd, bits;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ioctl(fd, TIOCMGET, &bits) != 0)
		err_return(errno);

	return ucv_int64_new(bits);
}

static uc_value_t *
uc_serial_mset(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *b = uc_fn_arg(1);
	int fd, bits;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ucv_type(b) != UC_INTEGER)
		err_return(EINVAL);

	bits = (int)ucv_int64_get(b);

	if (ioctl(fd, TIOCMSET, &bits) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
serial_modem_change(uc_vm_t *vm, size_t nargs, unsigned long req)
{
	uc_value_t *b = uc_fn_arg(1);
	int fd, bits;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ucv_type(b) != UC_INTEGER)
		err_return(EINVAL);

	bits = (int)ucv_int64_get(b);

	if (ioctl(fd, req, &bits) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_mbis(uc_vm_t *vm, size_t nargs)
{
	return serial_modem_change(vm, nargs, TIOCMBIS);
}

static uc_value_t *
uc_serial_mbic(uc_vm_t *vm, size_t nargs)
{
	return serial_modem_change(vm, nargs, TIOCMBIC);
}

static uc_value_t *
serial_modem_line(uc_vm_t *vm, size_t nargs, int bit)
{
	uc_value_t *on = uc_fn_arg(1);
	int fd;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ioctl(fd, ucv_is_truish(on) ? TIOCMBIS : TIOCMBIC, &bit) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_dtr(uc_vm_t *vm, size_t nargs)
{
	return serial_modem_line(vm, nargs, TIOCM_DTR);
}

static uc_value_t *
uc_serial_rts(uc_vm_t *vm, size_t nargs)
{
	return serial_modem_line(vm, nargs, TIOCM_RTS);
}

static uc_value_t *
uc_serial_sendbreak(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *dur = uc_fn_arg(1);
	int fd, d;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	d = (ucv_type(dur) == UC_INTEGER) ? (int)ucv_int64_get(dur) : 0;

	if (tcsendbreak(fd, d) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_drain(uc_vm_t *vm, size_t nargs)
{
	int fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (tcdrain(fd) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_serial_flush(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *q = uc_fn_arg(1);
	int fd, queue;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	queue = (ucv_type(q) == UC_INTEGER) ? (int)ucv_int64_get(q) : TCIOFLUSH;

	if (tcflush(fd, queue) != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
serial_queue_count(uc_vm_t *vm, size_t nargs, unsigned long req)
{
	int fd, n = 0;

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	if (ioctl(fd, req, &n) != 0)
		err_return(errno);

	return ucv_int64_new(n);
}

static uc_value_t *
uc_serial_input_waiting(uc_vm_t *vm, size_t nargs)
{
	return serial_queue_count(vm, nargs, TIOCINQ);
}

static uc_value_t *
uc_serial_output_waiting(uc_vm_t *vm, size_t nargs)
{
	return serial_queue_count(vm, nargs, TIOCOUTQ);
}

static const uc_function_list_t global_fns[] = {
	{ "error",       uc_serial_error },
	{ "isatty",      uc_serial_isatty },
	{ "attr",        uc_serial_attr },
	{ "setattr",     uc_serial_setattr },
	{ "setspeed",    uc_serial_setspeed },
	{ "setraw",      uc_serial_setraw },
	{ "setblocking", uc_serial_setblocking },
	{ "mget",        uc_serial_mget },
	{ "mset",        uc_serial_mset },
	{ "mbis",        uc_serial_mbis },
	{ "mbic",        uc_serial_mbic },
	{ "dtr",         uc_serial_dtr },
	{ "rts",         uc_serial_rts },
	{ "sendbreak",      uc_serial_sendbreak },
	{ "drain",          uc_serial_drain },
	{ "flush",          uc_serial_flush },
	{ "input_waiting",  uc_serial_input_waiting },
	{ "output_waiting", uc_serial_output_waiting },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

	#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

#ifdef TCSANOW
	ADD_CONST(TCSANOW);
#endif
#ifdef TCSADRAIN
	ADD_CONST(TCSADRAIN);
#endif
#ifdef TCSAFLUSH
	ADD_CONST(TCSAFLUSH);
#endif

#ifdef TCIFLUSH
	ADD_CONST(TCIFLUSH);
#endif
#ifdef TCOFLUSH
	ADD_CONST(TCOFLUSH);
#endif
#ifdef TCIOFLUSH
	ADD_CONST(TCIOFLUSH);
#endif

#ifdef CSIZE
	ADD_CONST(CSIZE);
#endif
#ifdef CS5
	ADD_CONST(CS5);
#endif
#ifdef CS6
	ADD_CONST(CS6);
#endif
#ifdef CS7
	ADD_CONST(CS7);
#endif
#ifdef CS8
	ADD_CONST(CS8);
#endif
#ifdef CSTOPB
	ADD_CONST(CSTOPB);
#endif
#ifdef CREAD
	ADD_CONST(CREAD);
#endif
#ifdef PARENB
	ADD_CONST(PARENB);
#endif
#ifdef PARODD
	ADD_CONST(PARODD);
#endif
#ifdef HUPCL
	ADD_CONST(HUPCL);
#endif
#ifdef CLOCAL
	ADD_CONST(CLOCAL);
#endif
#ifdef CRTSCTS
	ADD_CONST(CRTSCTS);
#endif
#ifdef CMSPAR
	ADD_CONST(CMSPAR);
#endif
#ifdef CBAUD
	ADD_CONST(CBAUD);
#endif
#ifdef CBAUDEX
	ADD_CONST(CBAUDEX);
#endif

#ifdef IGNBRK
	ADD_CONST(IGNBRK);
#endif
#ifdef BRKINT
	ADD_CONST(BRKINT);
#endif
#ifdef IGNPAR
	ADD_CONST(IGNPAR);
#endif
#ifdef PARMRK
	ADD_CONST(PARMRK);
#endif
#ifdef INPCK
	ADD_CONST(INPCK);
#endif
#ifdef ISTRIP
	ADD_CONST(ISTRIP);
#endif
#ifdef INLCR
	ADD_CONST(INLCR);
#endif
#ifdef IGNCR
	ADD_CONST(IGNCR);
#endif
#ifdef ICRNL
	ADD_CONST(ICRNL);
#endif
#ifdef IUCLC
	ADD_CONST(IUCLC);
#endif
#ifdef IXON
	ADD_CONST(IXON);
#endif
#ifdef IXANY
	ADD_CONST(IXANY);
#endif
#ifdef IXOFF
	ADD_CONST(IXOFF);
#endif
#ifdef IMAXBEL
	ADD_CONST(IMAXBEL);
#endif
#ifdef IUTF8
	ADD_CONST(IUTF8);
#endif

#ifdef OPOST
	ADD_CONST(OPOST);
#endif
#ifdef OLCUC
	ADD_CONST(OLCUC);
#endif
#ifdef ONLCR
	ADD_CONST(ONLCR);
#endif
#ifdef OCRNL
	ADD_CONST(OCRNL);
#endif
#ifdef ONOCR
	ADD_CONST(ONOCR);
#endif
#ifdef ONLRET
	ADD_CONST(ONLRET);
#endif
#ifdef OFILL
	ADD_CONST(OFILL);
#endif
#ifdef OFDEL
	ADD_CONST(OFDEL);
#endif

#ifdef ISIG
	ADD_CONST(ISIG);
#endif
#ifdef ICANON
	ADD_CONST(ICANON);
#endif
#ifdef ECHO
	ADD_CONST(ECHO);
#endif
#ifdef ECHOE
	ADD_CONST(ECHOE);
#endif
#ifdef ECHOK
	ADD_CONST(ECHOK);
#endif
#ifdef ECHONL
	ADD_CONST(ECHONL);
#endif
#ifdef ECHOCTL
	ADD_CONST(ECHOCTL);
#endif
#ifdef ECHOKE
	ADD_CONST(ECHOKE);
#endif
#ifdef NOFLSH
	ADD_CONST(NOFLSH);
#endif
#ifdef TOSTOP
	ADD_CONST(TOSTOP);
#endif
#ifdef IEXTEN
	ADD_CONST(IEXTEN);
#endif

#ifdef VINTR
	ADD_CONST(VINTR);
#endif
#ifdef VQUIT
	ADD_CONST(VQUIT);
#endif
#ifdef VERASE
	ADD_CONST(VERASE);
#endif
#ifdef VKILL
	ADD_CONST(VKILL);
#endif
#ifdef VEOF
	ADD_CONST(VEOF);
#endif
#ifdef VTIME
	ADD_CONST(VTIME);
#endif
#ifdef VMIN
	ADD_CONST(VMIN);
#endif
#ifdef VSWTC
	ADD_CONST(VSWTC);
#endif
#ifdef VSTART
	ADD_CONST(VSTART);
#endif
#ifdef VSTOP
	ADD_CONST(VSTOP);
#endif
#ifdef VSUSP
	ADD_CONST(VSUSP);
#endif
#ifdef VEOL
	ADD_CONST(VEOL);
#endif
#ifdef VREPRINT
	ADD_CONST(VREPRINT);
#endif
#ifdef VDISCARD
	ADD_CONST(VDISCARD);
#endif
#ifdef VWERASE
	ADD_CONST(VWERASE);
#endif
#ifdef VLNEXT
	ADD_CONST(VLNEXT);
#endif
#ifdef VEOL2
	ADD_CONST(VEOL2);
#endif
#ifdef NCCS
	ADD_CONST(NCCS);
#endif

#ifdef B0
	ADD_CONST(B0);
#endif
#ifdef B50
	ADD_CONST(B50);
#endif
#ifdef B75
	ADD_CONST(B75);
#endif
#ifdef B110
	ADD_CONST(B110);
#endif
#ifdef B134
	ADD_CONST(B134);
#endif
#ifdef B150
	ADD_CONST(B150);
#endif
#ifdef B200
	ADD_CONST(B200);
#endif
#ifdef B300
	ADD_CONST(B300);
#endif
#ifdef B600
	ADD_CONST(B600);
#endif
#ifdef B1200
	ADD_CONST(B1200);
#endif
#ifdef B1800
	ADD_CONST(B1800);
#endif
#ifdef B2400
	ADD_CONST(B2400);
#endif
#ifdef B4800
	ADD_CONST(B4800);
#endif
#ifdef B9600
	ADD_CONST(B9600);
#endif
#ifdef B19200
	ADD_CONST(B19200);
#endif
#ifdef B38400
	ADD_CONST(B38400);
#endif
#ifdef B57600
	ADD_CONST(B57600);
#endif
#ifdef B115200
	ADD_CONST(B115200);
#endif
#ifdef B230400
	ADD_CONST(B230400);
#endif
#ifdef B460800
	ADD_CONST(B460800);
#endif
#ifdef B500000
	ADD_CONST(B500000);
#endif
#ifdef B576000
	ADD_CONST(B576000);
#endif
#ifdef B921600
	ADD_CONST(B921600);
#endif
#ifdef B1000000
	ADD_CONST(B1000000);
#endif
#ifdef B1152000
	ADD_CONST(B1152000);
#endif
#ifdef B1500000
	ADD_CONST(B1500000);
#endif
#ifdef B2000000
	ADD_CONST(B2000000);
#endif
#ifdef B2500000
	ADD_CONST(B2500000);
#endif
#ifdef B3000000
	ADD_CONST(B3000000);
#endif
#ifdef B3500000
	ADD_CONST(B3500000);
#endif
#ifdef B4000000
	ADD_CONST(B4000000);
#endif

#ifdef TIOCM_LE
	ADD_CONST(TIOCM_LE);
#endif
#ifdef TIOCM_DTR
	ADD_CONST(TIOCM_DTR);
#endif
#ifdef TIOCM_RTS
	ADD_CONST(TIOCM_RTS);
#endif
#ifdef TIOCM_ST
	ADD_CONST(TIOCM_ST);
#endif
#ifdef TIOCM_SR
	ADD_CONST(TIOCM_SR);
#endif
#ifdef TIOCM_CTS
	ADD_CONST(TIOCM_CTS);
#endif
#ifdef TIOCM_CAR
	ADD_CONST(TIOCM_CAR);
#endif
#ifdef TIOCM_CD
	ADD_CONST(TIOCM_CD);
#endif
#ifdef TIOCM_RNG
	ADD_CONST(TIOCM_RNG);
#endif
#ifdef TIOCM_RI
	ADD_CONST(TIOCM_RI);
#endif
#ifdef TIOCM_DSR
	ADD_CONST(TIOCM_DSR);
#endif

	#undef ADD_CONST
}
