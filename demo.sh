#!/bin/bash
#
# V2Ray Detection System - Demo Control Script
# One-click commands to control the entire system
#

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "======================================================"
    echo "   V2Ray Detection System - Demo Control Panel"
    echo "======================================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        echo "Please install Docker Desktop: https://www.docker.com/products/docker-desktop"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        echo "Please start Docker Desktop"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not installed"
        exit 1
    fi

    print_success "Docker is ready"
}

# Start the system
start_system() {
    print_banner
    print_info "Starting V2Ray Detection System..."

    check_docker

    # Create necessary directories
    mkdir -p data logs reports

    # Start containers
    print_info "Building and starting containers..."
    docker-compose up -d --build detector dashboard

    # Wait for services to be ready
    print_info "Waiting for services to start..."
    sleep 5

    # Check if services are running
    if docker-compose ps | grep -q "Up"; then
        print_success "System started successfully!"
        echo ""
        echo -e "${GREEN}Dashboard URL: http://localhost:3000${NC}"
        echo ""
        echo "Available commands:"
        echo "  ./demo.sh attack    - Start attack simulation"
        echo "  ./demo.sh stop      - Stop attack"
        echo "  ./demo.sh reset     - Reset all data"
        echo "  ./demo.sh logs      - View detector logs"
        echo "  ./demo.sh down      - Shutdown system"
        echo ""
        print_info "Opening dashboard in browser..."
        sleep 2
        open http://localhost:3000 2>/dev/null || xdg-open http://localhost:3000 2>/dev/null || echo "Please open http://localhost:3000 in your browser"
    else
        print_error "Failed to start system"
        docker-compose logs
        exit 1
    fi
}

# Start attack simulation
start_attack() {
    print_info "Starting aggressive attack simulation..."

    if ! docker-compose ps | grep -q "detector.*Up"; then
        print_error "System is not running. Start it first with: ./demo.sh start"
        exit 1
    fi

    # Start attacker container
    docker-compose up -d attacker

    print_success "Attack simulation started!"
    echo ""
    echo "Watch the dashboard for real-time detection: http://localhost:3000"
    echo "Stop attack with: ./demo.sh stop"
    echo ""
    print_info "View attack logs:"
    echo "  docker-compose logs -f attacker"
}

# Stop attack
stop_attack() {
    print_info "Stopping attack simulation..."

    docker-compose stop attacker
    docker-compose rm -f attacker

    print_success "Attack stopped"
}

# Reset all data
reset_data() {
    print_info "Resetting all data..."

    # Stop containers
    docker-compose stop

    # Remove data files
    rm -rf data/* logs/*

    # Restart containers
    docker-compose up -d detector dashboard

    print_success "All data reset. System restarted."
}

# View logs
view_logs() {
    SERVICE=${1:-detector}
    print_info "Viewing logs for $SERVICE..."
    docker-compose logs -f "$SERVICE"
}

# Shutdown system
shutdown_system() {
    print_info "Shutting down V2Ray Detection System..."

    docker-compose down

    print_success "System shut down"
}

# Generate report
generate_report() {
    print_info "Generating detection report..."

    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    REPORT_FILE="reports/detection_report_${TIMESTAMP}.html"

    # Copy data files to reports
    if [ -f "data/alerts.json" ]; then
        cp data/alerts.json "reports/alerts_${TIMESTAMP}.json"
        print_success "Report generated: $REPORT_FILE"
        echo "JSON data exported: reports/alerts_${TIMESTAMP}.json"
    else
        print_error "No data available for report"
    fi
}

# Status check
check_status() {
    print_banner
    echo "System Status:"
    echo ""
    docker-compose ps
    echo ""

    if docker-compose ps | grep -q "detector.*Up"; then
        print_success "Detector is running"
    else
        print_error "Detector is not running"
    fi

    if docker-compose ps | grep -q "dashboard.*Up"; then
        print_success "Dashboard is running"
    else
        print_error "Dashboard is not running"
    fi

    if docker-compose ps | grep -q "attacker.*Up"; then
        print_success "Attack simulation is active"
    else
        print_info "Attack simulation is inactive"
    fi
}

# Show help
show_help() {
    print_banner
    echo "Usage: ./demo.sh [command]"
    echo ""
    echo "Commands:"
    echo "  start    - Start the detection system and dashboard"
    echo "  attack   - Launch attack simulation"
    echo "  stop     - Stop attack simulation"
    echo "  reset    - Reset all data and restart"
    echo "  logs     - View detector logs (or specify: logs attacker)"
    echo "  status   - Check system status"
    echo "  report   - Generate detection report"
    echo "  down     - Shutdown all containers"
    echo "  help     - Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./demo.sh start         # Start the system"
    echo "  ./demo.sh attack        # Start attack"
    echo "  ./demo.sh logs detector # View detector logs"
    echo "  ./demo.sh down          # Shutdown"
    echo ""
}

# Main command dispatcher
case "${1:-}" in
    start)
        start_system
        ;;
    attack)
        start_attack
        ;;
    stop)
        stop_attack
        ;;
    reset)
        reset_data
        ;;
    logs)
        view_logs "${2:-detector}"
        ;;
    status)
        check_status
        ;;
    report)
        generate_report
        ;;
    down)
        shutdown_system
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
