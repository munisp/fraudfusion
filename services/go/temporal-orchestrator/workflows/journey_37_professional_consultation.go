package workflows

import (
	"context"
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Journey37Input represents the input for Journey 37: Professional Consultation Booking
type Journey37Input struct {
	UserID           string                 `json:"user_id"`
	ProfessionalType string                 `json:"professional_type"` // lawyer, surveyor, estate_agent
	State            string                 `json:"state"`
	Specialization   string                 `json:"specialization"`
	PreferredDate    string                 `json:"preferred_date"` // YYYY-MM-DD
	PreferredTime    string                 `json:"preferred_time"` // HH:MM
	IssueDescription string                 `json:"issue_description"`
	UrgencyLevel     string                 `json:"urgency_level"`     // low, medium, high, critical
	ConsultationType string                 `json:"consultation_type"` // virtual, in_person, phone
	Budget           float64                `json:"budget,omitempty"`
	MinRating        float64                `json:"min_rating,omitempty"` // Default: 4.0
	Context          map[string]interface{} `json:"context"`
}

// Journey37Output represents the output for Journey 37
type Journey37Output struct {
	JourneyID        string                `json:"journey_id"`
	Status           string                `json:"status"`
	BookingID        string                `json:"booking_id"`
	Professional     *ProfessionalDetails  `json:"professional,omitempty"`
	Appointment      *AppointmentDetails   `json:"appointment,omitempty"`
	AlternativePros  []ProfessionalDetails `json:"alternative_professionals,omitempty"`
	PaymentRequired  bool                  `json:"payment_required"`
	PaymentAmount    float64               `json:"payment_amount,omitempty"`
	PaymentLink      string                `json:"payment_link,omitempty"`
	ConfirmationSent bool                  `json:"confirmation_sent"`
	ExecutionTime    float64               `json:"execution_time"`
	Timestamp        time.Time             `json:"timestamp"`
}

// ProfessionalDetails represents detailed information about a professional
type ProfessionalDetails struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Type            string             `json:"type"`
	License         string             `json:"license"`
	LicenseVerified bool               `json:"license_verified"`
	Rating          float64            `json:"rating"`
	ReviewCount     int                `json:"review_count"`
	Specialization  string             `json:"specialization"`
	YearsExperience int                `json:"years_experience"`
	State           string             `json:"state"`
	Contact         ContactInfo        `json:"contact"`
	Availability    []AvailabilitySlot `json:"availability"`
	ConsultationFee float64            `json:"consultation_fee"`
	Languages       []string           `json:"languages"`
	SuccessRate     float64            `json:"success_rate,omitempty"`
	CasesHandled    int                `json:"cases_handled,omitempty"`
	Certifications  []string           `json:"certifications,omitempty"`
	ProfileURL      string             `json:"profile_url"`
}

// ContactInfo represents contact information
type ContactInfo struct {
	Phone    string `json:"phone"`
	Email    string `json:"email"`
	WhatsApp string `json:"whatsapp,omitempty"`
	Office   string `json:"office,omitempty"`
	Website  string `json:"website,omitempty"`
}

// AvailabilitySlot represents an available time slot
type AvailabilitySlot struct {
	Date      string `json:"date"`       // YYYY-MM-DD
	StartTime string `json:"start_time"` // HH:MM
	EndTime   string `json:"end_time"`   // HH:MM
	Type      string `json:"type"`       // virtual, in_person, phone
	Available bool   `json:"available"`
}

// AppointmentDetails represents booking details
type AppointmentDetails struct {
	Date             string `json:"date"`
	Time             string `json:"time"`
	Duration         int    `json:"duration"` // minutes
	Type             string `json:"type"`
	Location         string `json:"location,omitempty"`
	MeetingLink      string `json:"meeting_link,omitempty"`
	Instructions     string `json:"instructions,omitempty"`
	CancellationLink string `json:"cancellation_link,omitempty"`
}

// Journey37ProfessionalConsultationWorkflow implements the professional consultation booking workflow
func Journey37ProfessionalConsultationWorkflow(ctx workflow.Context, input Journey37Input) (*Journey37Output, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting Journey 37: Professional Consultation Booking",
		"userID", input.UserID,
		"professionalType", input.ProfessionalType,
		"state", input.State,
		"urgencyLevel", input.UrgencyLevel)

	startTime := workflow.Now(ctx)
	output := &Journey37Output{
		JourneyID: "journey-37",
		Status:    "in_progress",
		Timestamp: startTime,
	}

	// Configure activity options
	activityOptions := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    15 * time.Second,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, activityOptions)

	// Set default minimum rating if not provided
	if input.MinRating == 0 {
		input.MinRating = 4.0
	}

	// Step 1: Validate user request
	logger.Info("Step 1: Validating user request")
	var validationResult map[string]interface{}
	validationInput := map[string]interface{}{
		"user_id":           input.UserID,
		"professional_type": input.ProfessionalType,
		"state":             input.State,
		"preferred_date":    input.PreferredDate,
	}
	err := workflow.ExecuteActivity(ctx, ValidateBookingRequestActivity, validationInput).Get(ctx, &validationResult)
	if err != nil {
		logger.Error("Request validation failed", "error", err)
		output.Status = "failed"
		return output, fmt.Errorf("validation failed: %w", err)
	}

	if valid, ok := validationResult["valid"].(bool); !ok || !valid {
		logger.Error("Invalid booking request", "reason", validationResult["reason"])
		output.Status = "failed"
		return output, fmt.Errorf("invalid request: %v", validationResult["reason"])
	}
	logger.Info("Request validated successfully")

	// Step 2: Search Professional Directory
	logger.Info("Step 2: Searching Professional Directory")
	var professionals []ProfessionalDetails
	searchInput := map[string]interface{}{
		"professional_type": input.ProfessionalType,
		"state":             input.State,
		"specialization":    input.Specialization,
		"min_rating":        input.MinRating,
		"max_results":       10,
		"sort_by":           "rating", // rating, experience, success_rate
	}
	err = workflow.ExecuteActivity(ctx, SearchProfessionalDirectoryActivity, searchInput).Get(ctx, &professionals)
	if err != nil {
		logger.Error("Failed to search professional directory", "error", err)
		output.Status = "failed"
		return output, fmt.Errorf("directory search failed: %w", err)
	}

	if len(professionals) == 0 {
		logger.Warn("No professionals found matching criteria")
		output.Status = "no_professionals_found"
		return output, fmt.Errorf("no professionals available for: %s in %s", input.ProfessionalType, input.State)
	}

	logger.Info("Professionals found", "count", len(professionals))

	// Step 3: Check professional availability
	logger.Info("Step 3: Checking professional availability")
	var availableProfessional *ProfessionalDetails
	var availableSlot *AvailabilitySlot

	// Fan out all availability checks concurrently, then evaluate results in
	// directory order so the highest-ranked available professional still wins
	// (same selection semantics as the previous sequential loop).
	availabilityFutures := make([]workflow.Future, len(professionals))
	for i, pro := range professionals {
		availabilityInput := map[string]interface{}{
			"professional_id":   pro.ID,
			"preferred_date":    input.PreferredDate,
			"preferred_time":    input.PreferredTime,
			"consultation_type": input.ConsultationType,
			"date_range_days":   7, // Check next 7 days
		}
		availabilityFutures[i] = workflow.ExecuteActivity(ctx, CheckProfessionalAvailabilityActivity, availabilityInput)
	}

	availabilityErrors := 0
	for i, pro := range professionals {
		var availability []AvailabilitySlot
		if err := availabilityFutures[i].Get(ctx, &availability); err != nil {
			logger.Warn("Failed to check availability", "professional", pro.Name, "error", err)
			availabilityErrors++
			continue
		}

		// Find matching slot
		for _, slot := range availability {
			if slot.Available && slot.Type == input.ConsultationType {
				if input.PreferredDate == "" || slot.Date == input.PreferredDate {
					availableProfessional = &professionals[i]
					availableProfessional.Availability = availability
					availableSlot = &slot
					logger.Info("Available professional found", "name", pro.Name, "date", slot.Date, "time", slot.StartTime)
					break
				}
			}
		}

		if availableProfessional != nil {
			break
		}
	}

	if availableProfessional == nil {
		if availabilityErrors == len(professionals) {
			// Every availability lookup failed: this is a service outage, not a
			// genuine lack of availability. Fail loudly instead of reporting
			// "no_availability" on fabricated absence of data.
			output.Status = "failed"
			return output, fmt.Errorf("availability checks failed for all %d professionals", availabilityErrors)
		}
		logger.Warn("No available professionals found")
		output.Status = "no_availability"
		output.AlternativePros = professionals[:min(3, len(professionals))] // Return top 3 alternatives
		return output, fmt.Errorf("no professionals available on preferred date")
	}

	output.Professional = availableProfessional

	// Step 4: Create booking
	logger.Info("Step 4: Creating booking")
	var bookingResult map[string]interface{}
	bookingInput := map[string]interface{}{
		"user_id":           input.UserID,
		"professional_id":   availableProfessional.ID,
		"date":              availableSlot.Date,
		"start_time":        availableSlot.StartTime,
		"end_time":          availableSlot.EndTime,
		"consultation_type": input.ConsultationType,
		"issue_description": input.IssueDescription,
		"urgency_level":     input.UrgencyLevel,
	}

	err = workflow.ExecuteActivity(ctx, CreateBookingActivity, bookingInput).Get(ctx, &bookingResult)
	if err != nil {
		logger.Error("Failed to create booking", "error", err)
		output.Status = "booking_failed"
		return output, fmt.Errorf("booking creation failed: %w", err)
	}

	bookingID, _ := bookingResult["booking_id"].(string)
	if bookingID == "" {
		output.Status = "booking_failed"
		return output, fmt.Errorf("booking service response lacks booking_id")
	}
	output.BookingID = bookingID
	output.Appointment = &AppointmentDetails{
		Date:             availableSlot.Date,
		Time:             availableSlot.StartTime,
		Duration:         60, // Default 60 minutes
		Type:             input.ConsultationType,
		Location:         getStringOrEmpty(bookingResult, "location"),
		MeetingLink:      getStringOrEmpty(bookingResult, "meeting_link"),
		Instructions:     getStringOrEmpty(bookingResult, "instructions"),
		CancellationLink: fmt.Sprintf("https://fraudfusion.io/bookings/%s/cancel", output.BookingID),
	}

	logger.Info("Booking created successfully", "bookingID", output.BookingID)

	// Check if payment is required
	output.PaymentRequired = availableProfessional.ConsultationFee > 0
	if output.PaymentRequired {
		output.PaymentAmount = availableProfessional.ConsultationFee
		output.PaymentLink = fmt.Sprintf("https://fraudfusion.io/payments/%s", output.BookingID)
		logger.Info("Payment required", "amount", output.PaymentAmount)
	}

	// Step 5: Send notifications
	logger.Info("Step 5: Sending notifications")
	var notificationResult map[string]interface{}
	notificationInput := map[string]interface{}{
		"booking_id":      output.BookingID,
		"user_id":         input.UserID,
		"professional_id": availableProfessional.ID,
		"appointment":     output.Appointment,
		"professional":    availableProfessional,
	}

	// Use longer timeout for notification activity
	notificationCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 45 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    2 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    30 * time.Second,
			MaximumAttempts:    5,
		},
	})

	err = workflow.ExecuteActivity(notificationCtx, SendBookingNotificationsActivity, notificationInput).Get(notificationCtx, &notificationResult)
	if err != nil {
		logger.Warn("Failed to send notifications", "error", err)
		// Don't fail the workflow if notifications fail
		output.ConfirmationSent = false
	} else {
		sent, _ := notificationResult["sent"].(bool)
		output.ConfirmationSent = sent
		logger.Info("Notifications sent successfully")
	}

	// Get alternative professionals for user reference
	if len(professionals) > 1 {
		alternativeCount := min(3, len(professionals)-1)
		output.AlternativePros = make([]ProfessionalDetails, 0, alternativeCount)
		for i, pro := range professionals {
			if pro.ID != availableProfessional.ID && len(output.AlternativePros) < alternativeCount {
				output.AlternativePros = append(output.AlternativePros, professionals[i])
			}
		}
	}

	// Calculate execution time
	endTime := workflow.Now(ctx)
	output.ExecutionTime = endTime.Sub(startTime).Seconds()
	output.Status = "completed"

	logger.Info("Journey 37 completed successfully",
		"bookingID", output.BookingID,
		"professional", availableProfessional.Name,
		"executionTime", output.ExecutionTime)

	return output, nil
}

// Activity implementations

// ValidateBookingRequestActivity validates the booking request
func ValidateBookingRequestActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	userID, _ := input["user_id"].(string)
	professionalType, _ := input["professional_type"].(string)
	state, _ := input["state"].(string)
	if userID == "" {
		return map[string]interface{}{"valid": false, "reason": "user_id is required"}, nil
	}

	// Validate professional type
	validTypes := []string{"lawyer", "surveyor", "estate_agent"}
	validType := false
	for _, t := range validTypes {
		if professionalType == t {
			validType = true
			break
		}
	}

	if !validType {
		return map[string]interface{}{
			"valid":  false,
			"reason": fmt.Sprintf("Invalid professional type: %s. Must be one of: lawyer, surveyor, estate_agent", professionalType),
		}, nil
	}

	// Validate state
	validStates := []string{"Lagos", "Abuja", "Rivers", "Ogun", "Kano"} // Add all 36 states
	validState := false
	for _, s := range validStates {
		if state == s {
			validState = true
			break
		}
	}

	if !validState {
		return map[string]interface{}{
			"valid":  false,
			"reason": fmt.Sprintf("Service not available in state: %s", state),
		}, nil
	}

	// Check user eligibility (e.g., not banned, account in good standing)
	// Call user service: http://user-service:8010/api/v1/users/{userID}/eligibility

	return map[string]interface{}{
		"valid":   true,
		"user_id": userID,
	}, nil
}

// SearchProfessionalDirectoryActivity searches the professional directory
// served by the land-verification-service. It fails loudly when the service
// is unconfigured or errors — professionals are never fabricated locally.
func SearchProfessionalDirectoryActivity(ctx context.Context, input map[string]interface{}) ([]ProfessionalDetails, error) {
	professionalType, _ := input["professional_type"].(string)
	state, _ := input["state"].(string)
	if professionalType == "" || state == "" {
		return nil, fmt.Errorf("professional_type and state are required")
	}

	var response struct {
		Professionals []ProfessionalDetails `json:"professionals"`
	}
	if err := callServiceJSON(ctx, LandVerificationURLEnv, "/api/v1/professionals/search", input, &response); err != nil {
		return nil, fmt.Errorf("professional directory search: %w", err)
	}

	// Defensive re-filter: enforce the requested type/state/rating even if the
	// downstream service returns a broader result set.
	minRating, _ := input["min_rating"].(float64)
	filtered := []ProfessionalDetails{}
	for _, pro := range response.Professionals {
		if pro.Type == professionalType && pro.State == state && pro.Rating >= minRating {
			filtered = append(filtered, pro)
		}
	}
	return filtered, nil
}

// CheckProfessionalAvailabilityActivity checks a professional's availability
// via the directory service. Fails loudly on any downstream error.
func CheckProfessionalAvailabilityActivity(ctx context.Context, input map[string]interface{}) ([]AvailabilitySlot, error) {
	professionalID, _ := input["professional_id"].(string)
	consultationType, _ := input["consultation_type"].(string)
	if professionalID == "" || consultationType == "" {
		return nil, fmt.Errorf("professional_id and consultation_type are required")
	}

	var response struct {
		Slots []AvailabilitySlot `json:"slots"`
	}
	if err := callServiceJSON(ctx, LandVerificationURLEnv,
		"/api/v1/professionals/"+professionalID+"/availability", input, &response); err != nil {
		return nil, fmt.Errorf("professional availability lookup: %w", err)
	}
	return response.Slots, nil
}

// CreateBookingActivity creates a booking via the booking service. The
// booking ID always comes from that service; nothing is synthesized locally.
func CreateBookingActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	userID, _ := input["user_id"].(string)
	professionalID, _ := input["professional_id"].(string)
	date, _ := input["date"].(string)
	startTime, _ := input["start_time"].(string)
	consultationType, _ := input["consultation_type"].(string)
	if userID == "" || professionalID == "" || date == "" || startTime == "" || consultationType == "" {
		return nil, fmt.Errorf("user_id, professional_id, date, start_time, and consultation_type are required")
	}

	var booking map[string]interface{}
	if err := callServiceJSON(ctx, BookingServiceURLEnv, "/api/v1/bookings", input, &booking); err != nil {
		return nil, fmt.Errorf("booking creation: %w", err)
	}
	if bookingID, _ := booking["booking_id"].(string); bookingID == "" {
		return nil, fmt.Errorf("booking service response lacks booking_id")
	}
	return booking, nil
}

// SendBookingNotificationsActivity sends notifications via the notification
// service. Fails loudly when the service is unconfigured or errors.
func SendBookingNotificationsActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	bookingID, _ := input["booking_id"].(string)
	userID, _ := input["user_id"].(string)
	professionalID, _ := input["professional_id"].(string)
	if bookingID == "" || userID == "" || professionalID == "" {
		return nil, fmt.Errorf("booking_id, user_id, and professional_id are required")
	}

	var result map[string]interface{}
	if err := callServiceJSON(ctx, NotificationServiceURLEnv, "/api/v1/notifications/send", input, &result); err != nil {
		return nil, fmt.Errorf("booking notification: %w", err)
	}
	if _, ok := result["sent"].(bool); !ok {
		return nil, fmt.Errorf("notification service response lacks sent flag")
	}
	return result, nil
}


// Helper functions

func getStringOrEmpty(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// RegisterJourney37Workflow registers the workflow and activities with Temporal
func RegisterJourney37Workflow(worker worker.Worker) {
	worker.RegisterWorkflow(Journey37ProfessionalConsultationWorkflow)
	worker.RegisterActivity(ValidateBookingRequestActivity)
	worker.RegisterActivity(SearchProfessionalDirectoryActivity)
	worker.RegisterActivity(CheckProfessionalAvailabilityActivity)
	worker.RegisterActivity(CreateBookingActivity)
	worker.RegisterActivity(SendBookingNotificationsActivity)
}
