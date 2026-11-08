CREATE SCHEMA "analysis";
--> statement-breakpoint
CREATE SCHEMA "audit";
--> statement-breakpoint
CREATE SCHEMA "auth";
--> statement-breakpoint
CREATE SCHEMA "ingest";
--> statement-breakpoint
CREATE TYPE "analysis"."finding_status" AS ENUM('pending_review', 'confirmed', 'false_positive');--> statement-breakpoint
CREATE TYPE "analysis"."l1_verdict" AS ENUM('likely_true_positive', 'needs_context', 'likely_false_positive');--> statement-breakpoint
CREATE TYPE "auth"."role" AS ENUM('admin', 'analyst');--> statement-breakpoint
CREATE TYPE "analysis"."severity" AS ENUM('critical', 'high', 'medium', 'low');--> statement-breakpoint
CREATE TABLE "analysis"."analyses" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"upload_id" uuid NOT NULL,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"status" varchar(16) DEFAULT 'running' NOT NULL,
	"engine_version" varchar(16) NOT NULL,
	"stats" jsonb,
	"incidents" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"data_quality" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"ai_status" varchar(16) DEFAULT 'disabled' NOT NULL,
	"ai_model" varchar(64),
	"ai_error" text,
	"ai_rejected" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"executive_summary" text,
	"general_recommendations" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error" text
);
--> statement-breakpoint
CREATE TABLE "audit"."audit_log" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL,
	"user_id" uuid,
	"username" varchar(64),
	"action" varchar(64) NOT NULL,
	"entity_type" varchar(32),
	"entity_id" varchar(64),
	"ip" varchar(64),
	"details" jsonb
);
--> statement-breakpoint
CREATE TABLE "analysis"."finding_evidence" (
	"finding_id" uuid NOT NULL,
	"event_id" bigint NOT NULL,
	"log_id" varchar(64) NOT NULL,
	CONSTRAINT "finding_evidence_finding_id_event_id_pk" PRIMARY KEY("finding_id","event_id")
);
--> statement-breakpoint
CREATE TABLE "analysis"."findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"analysis_id" uuid NOT NULL,
	"rule_id" varchar(64) NOT NULL,
	"title" text NOT NULL,
	"severity" "analysis"."severity" NOT NULL,
	"score" integer NOT NULL,
	"score_factors" jsonb NOT NULL,
	"justification" text NOT NULL,
	"mitre" jsonb NOT NULL,
	"entities" jsonb NOT NULL,
	"first_seen" timestamp,
	"last_seen" timestamp,
	"event_count" integer NOT NULL,
	"summary" text NOT NULL,
	"technical_explanation" text NOT NULL,
	"impact" text NOT NULL,
	"action_plan" jsonb NOT NULL,
	"incident_key" varchar(32),
	"narrative_source" varchar(8) DEFAULT 'engine' NOT NULL,
	"l1_verdict" "analysis"."l1_verdict",
	"l1_rationale" text,
	"status" "analysis"."finding_status" DEFAULT 'pending_review' NOT NULL,
	"severity_override" "analysis"."severity",
	"analyst_notes" text,
	"reviewed_by" uuid,
	"reviewed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "ingest"."log_events" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"upload_id" uuid NOT NULL,
	"row_number" integer NOT NULL,
	"log_id" varchar(64) NOT NULL,
	"ts" timestamp,
	"ts_raw" varchar(64),
	"hostname" varchar(128),
	"event_id" varchar(64),
	"user_name" varchar(256),
	"source_ip" varchar(64),
	"destination" varchar(512),
	"log_source" varchar(64),
	"description" text,
	"command_line" text,
	"result" varchar(64),
	"severity_src" varchar(32)
);
--> statement-breakpoint
CREATE TABLE "analysis"."reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"analysis_id" uuid NOT NULL,
	"generated_by" uuid NOT NULL,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"file_name" varchar(255) NOT NULL,
	"file_path" text NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"size_bytes" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"ip" varchar(64),
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "ingest"."uploads" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"original_name" varchar(255) NOT NULL,
	"stored_name" varchar(255) NOT NULL,
	"stored_path" text NOT NULL,
	"upload_day" varchar(10) NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"size_bytes" integer NOT NULL,
	"sheet_name" varchar(128) NOT NULL,
	"row_count" integer NOT NULL,
	"uploaded_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"username" varchar(64) NOT NULL,
	"full_name" varchar(128) NOT NULL,
	"password_hash" text NOT NULL,
	"role" "auth"."role" DEFAULT 'analyst' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"must_change_password" boolean DEFAULT true NOT NULL,
	"failed_logins" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp with time zone,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid
);
--> statement-breakpoint
ALTER TABLE "analysis"."analyses" ADD CONSTRAINT "analyses_upload_id_uploads_id_fk" FOREIGN KEY ("upload_id") REFERENCES "ingest"."uploads"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."analyses" ADD CONSTRAINT "analyses_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."finding_evidence" ADD CONSTRAINT "finding_evidence_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "analysis"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."finding_evidence" ADD CONSTRAINT "finding_evidence_event_id_log_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "ingest"."log_events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."findings" ADD CONSTRAINT "findings_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "analysis"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."findings" ADD CONSTRAINT "findings_reviewed_by_users_id_fk" FOREIGN KEY ("reviewed_by") REFERENCES "auth"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingest"."log_events" ADD CONSTRAINT "log_events_upload_id_uploads_id_fk" FOREIGN KEY ("upload_id") REFERENCES "ingest"."uploads"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."reports" ADD CONSTRAINT "reports_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "analysis"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis"."reports" ADD CONSTRAINT "reports_generated_by_users_id_fk" FOREIGN KEY ("generated_by") REFERENCES "auth"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth"."sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingest"."uploads" ADD CONSTRAINT "uploads_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "analyses_upload_idx" ON "analysis"."analyses" USING btree ("upload_id");--> statement-breakpoint
CREATE INDEX "audit_at_idx" ON "audit"."audit_log" USING btree ("at");--> statement-breakpoint
CREATE INDEX "audit_user_idx" ON "audit"."audit_log" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "audit_action_idx" ON "audit"."audit_log" USING btree ("action");--> statement-breakpoint
CREATE INDEX "findings_analysis_idx" ON "analysis"."findings" USING btree ("analysis_id");--> statement-breakpoint
CREATE INDEX "log_events_upload_ts_idx" ON "ingest"."log_events" USING btree ("upload_id","ts");--> statement-breakpoint
CREATE INDEX "log_events_upload_logid_idx" ON "ingest"."log_events" USING btree ("upload_id","log_id");--> statement-breakpoint
CREATE INDEX "reports_analysis_idx" ON "analysis"."reports" USING btree ("analysis_id");--> statement-breakpoint
CREATE INDEX "sessions_user_idx" ON "auth"."sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "uploads_user_day_idx" ON "ingest"."uploads" USING btree ("user_id","upload_day");--> statement-breakpoint
CREATE INDEX "uploads_day_idx" ON "ingest"."uploads" USING btree ("upload_day");--> statement-breakpoint
CREATE UNIQUE INDEX "users_username_uq" ON "auth"."users" USING btree (lower("username"));