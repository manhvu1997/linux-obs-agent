package pgstat

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PgxDialer connects with dsnTemplate ("{port}" is replaced by the cluster's
// port). password (from password_file) overrides any in the DSN; it is never
// logged. Each connection runs with application_name=obs-agent and
// statement_timeout.
func PgxDialer(dsnTemplate, password string, statementTimeout time.Duration) Dialer {
	return func(ctx context.Context, port int) (Conn, error) {
		cfg, err := pgx.ParseConfig(strings.ReplaceAll(dsnTemplate, "{port}", strconv.Itoa(port)))
		if err != nil {
			return nil, fmt.Errorf("postgres.sql.dsn: %w", err) // ParseConfig redacts passwords
		}
		if password != "" {
			cfg.Password = password
		}
		cfg.RuntimeParams["application_name"] = "obs-agent"
		cfg.RuntimeParams["statement_timeout"] = strconv.FormatInt(statementTimeout.Milliseconds(), 10)
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return nil, mapErr(err)
		}
		return &pgxConn{c: c}, nil
	}
}

type pgxConn struct{ c *pgx.Conn }

func (p *pgxConn) Close() { _ = p.c.Close(context.Background()) }

func (p *pgxConn) Settings(ctx context.Context) (Settings, error) {
	var s Settings
	var track string
	err := p.c.QueryRow(ctx, `SELECT current_setting('server_version_num')::int,
		current_setting('block_size')::int, current_setting('track_io_timing'),
		current_setting('compute_query_id'), current_setting('synchronous_standby_names'),
		coalesce(current_setting('io_method', true), '')`).
		Scan(&s.VersionNum, &s.BlockSize, &track, &s.ComputeQueryID, &s.SyncStandbys, &s.IOMethod)
	s.TrackIOTiming = track == "on"
	return s, mapErr(err)
}

func (p *pgxConn) Statements(ctx context.Context, ids []int64, col string) ([]Row, error) {
	if col != "shared_blk_read_time" && col != "blk_read_time" {
		return nil, fmt.Errorf("unexpected read time column %q", col)
	}
	rows, err := p.c.Query(ctx, `SELECT queryid, calls, shared_blks_hit, shared_blks_read, temp_blks_written, `+col+`
		FROM pg_stat_statements(false) WHERE queryid = ANY($1)`, ids)
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Row, error) {
		var x Row
		var calls, hit, read, temp int64
		err := r.Scan(&x.QueryID, &calls, &hit, &read, &temp, &x.ReadTimeMs)
		x.Calls, x.SharedHit, x.SharedRead, x.TempWrite = uint64(calls), uint64(hit), uint64(read), uint64(temp)
		return x, err
	})
	return out, mapErr(err)
}

// mapErr classifies SQLSTATEs: 28000/28P01 authentication, 42P01/42883 the
// view or function does not exist (extension missing in this database).
func mapErr(err error) error {
	var pe *pgconn.PgError
	if err == nil || !errors.As(err, &pe) {
		return err
	}
	switch pe.Code {
	case "28000", "28P01":
		return fmt.Errorf("%w: %s", ErrAuth, pe.Message)
	case "42P01", "42883":
		return fmt.Errorf("%w: %s", ErrMissing, pe.Message)
	}
	return err
}
