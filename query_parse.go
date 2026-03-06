package caphouse

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// tokenize splits a filter string into tokens. Parentheses are always split
// off as individual tokens regardless of surrounding whitespace.
func tokenize(s string) []string {
	var tokens []string
	i := 0
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			i++
		case '(', ')':
			tokens = append(tokens, string(s[i]))
			i++
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' &&
				s[j] != '\n' && s[j] != '\r' &&
				s[j] != '(' && s[j] != ')' {
				j++
			}
			tokens = append(tokens, s[i:j])
			i = j
		}
	}
	return tokens
}

type parser struct {
	tokens []string
	pos    int
}

func newParser(s string) *parser {
	return &parser{tokens: tokenize(s)}
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *parser) next() string {
	t := p.peek()
	if t != "" {
		p.pos++
	}
	return t
}

func (p *parser) done() bool { return p.pos >= len(p.tokens) }

func (p *parser) expect(tok string) error {
	got := p.next()
	if !strings.EqualFold(got, tok) {
		return fmt.Errorf("expected %q, got %q", tok, got)
	}
	return nil
}

// Grammar:
//
//	expr     = or_expr
//	or_expr  = and_expr ('or'  and_expr)*
//	and_expr = not_expr ('and' not_expr)*
//	not_expr = 'not' not_expr | atom
//	atom     = '(' expr ')' | primitive
//	primitive = [dir] 'host' ip
//	          | [dir] 'port' number
//	          | 'time' rfc3339 'to' rfc3339
//	dir = 'src' | 'dst'

func (p *parser) parseExpr() (queryNode, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (queryNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (queryNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseNot() (queryNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		expr, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &notNode{expr}, nil
	}
	return p.parseAtom()
}

func (p *parser) parseAtom() (queryNode, error) {
	if p.peek() == "(" {
		p.next()
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		return expr, nil
	}
	return p.parsePrimitive()
}

func (p *parser) parsePrimitive() (queryNode, error) {
	tok := strings.ToLower(p.peek())
	if tok == "" {
		return nil, errors.New("unexpected end of filter expression")
	}

	// optional direction prefix
	var dir string
	if tok == "src" || tok == "dst" {
		dir = tok
		p.next()
		tok = strings.ToLower(p.peek())
	}

	switch tok {
	case "host":
		p.next()
		ip := p.next()
		if ip == "" {
			return nil, errors.New("expected IP address after 'host'")
		}
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address: %q", ip)
		}
		return &hostNode{dir: dir, ip: ip}, nil

	case "port":
		p.next()
		portStr := p.next()
		if portStr == "" {
			return nil, errors.New("expected port number after 'port'")
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
		return &portNode{dir: dir, port: uint16(port)}, nil

	case "time":
		if dir != "" {
			return nil, errors.New("'time' does not support a direction prefix")
		}
		p.next()
		fromStr := p.next()
		if fromStr == "" {
			return nil, errors.New("expected timestamp after 'time'")
		}
		if err := p.expect("to"); err != nil {
			return nil, err
		}
		toStr := p.next()
		if toStr == "" {
			return nil, errors.New("expected end timestamp after 'to'")
		}
		from, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return nil, fmt.Errorf("invalid time %q: %w", fromStr, err)
		}
		to, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			return nil, fmt.Errorf("invalid time %q: %w", toStr, err)
		}
		if !from.Before(to) {
			return nil, errors.New("filter 'time': 'from' must be before 'to'")
		}
		return &timeNode{from: from.UnixNano(), to: to.UnixNano()}, nil

	default:
		if dir != "" {
			return nil, fmt.Errorf("expected 'host' or 'port' after %q, got %q", dir, tok)
		}
		return nil, fmt.Errorf("unknown filter keyword %q", p.peek())
	}
}
