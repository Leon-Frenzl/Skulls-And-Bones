"use client";

import {
  createElement,
  forwardRef,
  useId,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type HTMLAttributes,
  type InputHTMLAttributes,
  type TextareaHTMLAttributes,
  type KeyboardEvent,
  type ReactNode,
  type CSSProperties,
} from "react";
import type { WorkbenchTheme } from "./workbench";
export {
  createWorkbenchItem,
  DEFAULT_WORKBENCH_THEMES,
  validateWorkbenchDesign,
  WORKBENCH_KINDS,
  type WorkbenchAlignment,
  type WorkbenchDesign,
  type WorkbenchGap,
  type WorkbenchItem,
  type WorkbenchKind,
  type WorkbenchTheme,
  type WorkbenchThemeMode,
  type WorkbenchViewport,
} from "./workbench";

export * from "./auth";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  busy?: boolean;
}

export function Button({
  variant = "secondary",
  size = "md",
  type = "button",
  busy = false,
  disabled,
  className = "",
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      {...props}
      aria-busy={busy || undefined}
      className={`sbui-button sbui-button--${variant} sbui-button--${size}${className ? ` ${className}` : ""}`}
      disabled={disabled || busy}
      type={type}
    >
      {busy && <span aria-hidden="true" className="sbui-spinner" />}
      {children}
    </button>
  );
}

export interface IconButtonProps extends ButtonProps {
  "aria-label": string;
}

export function IconButton({ className = "", ...props }: IconButtonProps) {
  return (
    <Button
      {...props}
      className={`sbui-icon-button${className ? ` ${className}` : ""}`}
    />
  );
}

export interface BrandLockupProps extends HTMLAttributes<HTMLSpanElement> {
  product?: string;
  size?: "sm" | "md" | "lg";
}

export function BrandLockup({
  product,
  size = "md",
  className = "",
  ...props
}: BrandLockupProps) {
  return (
    <span
      {...props}
      className={`sbui-brand-lockup sbui-brand-lockup--${size}${className ? ` ${className}` : ""}`}
    >
      <svg
        aria-hidden="true"
        className="sbui-brand-lockup__mark"
        fill="none"
        viewBox="32 32 196 196"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          clipRule="evenodd"
          d="M130 40C153.869 40 176.761 49.4821 193.64 66.3604C210.518 83.2387 220 106.131 220 130C220 153.869 210.518 176.761 193.64 193.64C176.761 210.518 153.869 220 130 220C106.131 220 83.2387 210.518 66.3604 193.64C49.4821 176.761 40 153.869 40 130C40 106.131 49.4821 83.2387 66.3604 66.3604C83.2387 49.4821 106.131 40 130 40ZM130 48C108.252 48 87.3952 56.6393 72.0172 72.0172C56.6393 87.3952 48 108.252 48 130C48 151.748 56.6393 172.605 72.0172 187.983C87.3952 203.361 108.252 212 130 212C151.748 212 172.605 203.361 187.983 187.983C203.361 172.605 212 151.748 212 130C212 108.252 203.361 87.3952 187.983 72.0172C172.605 56.6393 151.748 48 130 48Z"
          fill="currentColor"
          fillRule="evenodd"
        />
        <path
          clipRule="evenodd"
          d="M82 118C82 105.27 87.0571 93.0606 96.0589 84.0589C105.061 75.0571 117.27 70 130 70C142.73 70 154.939 75.0571 163.941 84.0589C172.943 93.0606 178 105.27 178 118V150L156 164V188H135V171H125V188H104V164L82 150V118ZM99 125L121 131V148L99 142V125ZM139 131L161 125V142L139 148V131ZM130 149L138 162H122L130 149Z"
          fill="currentColor"
          fillRule="evenodd"
        />
      </svg>
      <span className="sbui-brand-lockup__text">
        <span className="sbui-brand-lockup__name">SKULLS &amp; BONES</span>
        {product && (
          <span className="sbui-brand-lockup__product">{product}</span>
        )}
      </span>
    </span>
  );
}

export type BadgeVariant =
  | "neutral"
  | "accent"
  | "success"
  | "warning"
  | "danger";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

export function Badge({
  variant = "neutral",
  className = "",
  ...props
}: BadgeProps) {
  return (
    <span
      {...props}
      className={`sbui-badge sbui-badge--${variant}${className ? ` ${className}` : ""}`}
    />
  );
}

export interface CardProps extends HTMLAttributes<HTMLElement> {
  as?: "article" | "aside" | "div" | "section";
}

export function Card({ as = "section", className = "", ...props }: CardProps) {
  return createElement(as, {
    ...props,
    className: `sbui-card${className ? ` ${className}` : ""}`,
  });
}

export function CardHeader({
  className = "",
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...props}
      className={`sbui-card__header${className ? ` ${className}` : ""}`}
    />
  );
}

export function CardTitle({
  className = "",
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h2
      {...props}
      className={`sbui-card__title${className ? ` ${className}` : ""}`}
    />
  );
}

export function CardDescription({
  className = "",
  ...props
}: HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p
      {...props}
      className={`sbui-card__description${className ? ` ${className}` : ""}`}
    />
  );
}

export function CardContent({
  className = "",
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...props}
      className={`sbui-card__content${className ? ` ${className}` : ""}`}
    />
  );
}

export function CardFooter({
  className = "",
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...props}
      className={`sbui-card__footer${className ? ` ${className}` : ""}`}
    />
  );
}

export interface TextFieldProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  id?: string;
  label: string;
  helperText?: string;
  error?: string;
}

export function TextField({
  id,
  label,
  helperText,
  error,
  className = "",
  ...props
}: TextFieldProps) {
  const generatedId = useId();
  const inputId = id ?? `sbui-field-${generatedId}`;
  const messageId = `${inputId}-message`;
  const message = error ?? helperText;
  const describedBy = [props["aria-describedby"], message && messageId]
    .filter(Boolean)
    .join(" ") || undefined;

  return (
    <div className="sbui-field">
      <label className="sbui-field__label" htmlFor={inputId}>
        {label}
      </label>
      <input
        {...props}
        aria-describedby={describedBy}
        aria-invalid={error ? true : props["aria-invalid"]}
        className={`sbui-input${error ? " sbui-input--error" : ""}${className ? ` ${className}` : ""}`}
        id={inputId}
      />
      {message && (
        <p
          className={`sbui-field__message${error ? " sbui-field__message--error" : ""}`}
          id={messageId}
        >
          {message}
        </p>
      )}
    </div>
  );
}

export type FieldDensity = "comfortable" | "compact";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  density?: FieldDensity;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  function Input({ density = "comfortable", className = "", ...props }, ref) {
    return (
      <input
        {...props}
        className={`sbui-input${density === "compact" ? " sbui-input--compact" : ""}${className ? ` ${className}` : ""}`}
        ref={ref}
      />
    );
  },
);

export interface TextAreaProps
  extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  density?: FieldDensity;
}

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(
  function TextArea(
    { density = "comfortable", className = "", ...props },
    ref,
  ) {
    return (
      <textarea
        {...props}
        className={`sbui-textarea${density === "compact" ? " sbui-textarea--compact" : ""}${className ? ` ${className}` : ""}`}
        ref={ref}
      />
    );
  },
);

export interface SelectItem {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "value" | "onChange" | "children"> {
  items: readonly SelectItem[];
  value: string;
  onValueChange: (value: string) => void;
  placeholder?: string;
  name?: string;
}

export function Select({
  items,
  value,
  onValueChange,
  placeholder = "Auswählen …",
  name,
  id,
  className = "",
  disabled,
  onClick,
  onKeyDown,
  ...props
}: SelectProps) {
  const generatedId = useId();
  const triggerId = id ?? `sbui-select-${generatedId}`;
  const listboxId = `${triggerId}-listbox`;
  const rootRef = useRef<HTMLDivElement>(null);
  const typeaheadRef = useRef("");
  const typeaheadTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const selectedIndex = items.findIndex((item) => item.value === value);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(selectedIndex);
  const [placement, setPlacement] = useState<"top" | "bottom">("bottom");
  const selectedItem = selectedIndex < 0 ? undefined : items[selectedIndex];

  useEffect(() => {
    if (!open) return;

    const updatePlacement = () => {
      const bounds = rootRef.current?.getBoundingClientRect();
      if (!bounds) return;
      const spaceBelow = window.innerHeight - bounds.bottom;
      const spaceAbove = bounds.top;
      setPlacement(
        spaceBelow < Math.min(288, window.innerHeight * 0.5) &&
          spaceAbove > spaceBelow
          ? "top"
          : "bottom",
      );
    };
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    updatePlacement();
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("scroll", updatePlacement, true);
    window.addEventListener("resize", updatePlacement);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("scroll", updatePlacement, true);
      window.removeEventListener("resize", updatePlacement);
    };
  }, [open]);

  useEffect(
    () => () => {
      if (typeaheadTimerRef.current !== null) {
        clearTimeout(typeaheadTimerRef.current);
      }
    },
    [],
  );

  const moveActive = (direction: 1 | -1, fromIndex = activeIndex) => {
    for (let offset = 1; offset <= items.length; offset += 1) {
      const nextIndex =
        (fromIndex + direction * offset + items.length) % items.length;
      if (!items[nextIndex].disabled) {
        setActiveIndex(nextIndex);
        return;
      }
    }
  };

  const openAt = (index: number) => {
    const enabledIndex =
      index >= 0 && !items[index]?.disabled
        ? index
        : items.findIndex((item) => !item.disabled);
    setActiveIndex(enabledIndex);
    setOpen(true);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    onKeyDown?.(event);
    if (event.defaultPrevented || disabled) return;

    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const direction = event.key === "ArrowDown" ? 1 : -1;
      if (!open) {
        const start = selectedIndex >= 0 ? selectedIndex : direction > 0 ? -1 : 0;
        moveActive(direction, start);
        setOpen(true);
      } else {
        moveActive(direction);
      }
      return;
    }

    if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      const direction = event.key === "Home" ? 1 : -1;
      const start = event.key === "Home" ? -1 : items.length;
      for (let offset = 1; offset <= items.length; offset += 1) {
        const nextIndex = start + direction * offset;
        if (items[nextIndex] && !items[nextIndex].disabled) {
          setActiveIndex(nextIndex);
          setOpen(true);
          break;
        }
      }
      return;
    }

    if (event.key === "Escape" && open) {
      event.preventDefault();
      setOpen(false);
      return;
    }

    if (event.key === "Tab" && open) {
      setOpen(false);
      return;
    }

    if ((event.key === "Enter" || event.key === " ") && open) {
      event.preventDefault();
      const activeItem = items[activeIndex];
      if (activeItem && !activeItem.disabled) {
        onValueChange(activeItem.value);
        setOpen(false);
      }
      return;
    }

    if ((event.key === "Enter" || event.key === " ") && !open) {
      event.preventDefault();
      openAt(selectedIndex);
      return;
    }

    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const query = `${typeaheadRef.current}${event.key}`.toLocaleLowerCase();
      typeaheadRef.current = query;
      if (typeaheadTimerRef.current !== null) clearTimeout(typeaheadTimerRef.current);
      typeaheadTimerRef.current = setTimeout(() => {
        typeaheadRef.current = "";
        typeaheadTimerRef.current = null;
      }, 500);

      const start = open ? activeIndex : selectedIndex;
      for (let offset = 1; offset <= items.length; offset += 1) {
        const nextIndex = (start + offset + items.length) % items.length;
        const item = items[nextIndex];
        if (!item.disabled && item.label.toLocaleLowerCase().startsWith(query)) {
          event.preventDefault();
          setActiveIndex(nextIndex);
          setOpen(true);
          break;
        }
      }
    }
  };

  const handleOptionClick = (item: SelectItem) => {
    if (item.disabled) return;
    onValueChange(item.value);
    setOpen(false);
  };

  return (
    <div
      className={`sbui-select${className ? ` ${className}` : ""}`}
      ref={rootRef}
    >
      {name && <input name={name} type="hidden" value={value} />}
      <button
        {...props}
        aria-activedescendant={open && activeIndex >= 0 ? `${listboxId}-option-${activeIndex}` : undefined}
        aria-controls={listboxId}
        aria-expanded={open}
        aria-haspopup="listbox"
        className="sbui-select__trigger"
        disabled={disabled}
        id={triggerId}
        onClick={(event) => {
          onClick?.(event);
          if (event.defaultPrevented) return;
          if (open) {
            setOpen(false);
          } else {
            openAt(selectedIndex);
          }
        }}
        onKeyDown={handleKeyDown}
        role="combobox"
        type="button"
      >
        <span className={!selectedItem ? "sbui-select__placeholder" : undefined}>
          {selectedItem?.label ?? placeholder}
        </span>
        <span aria-hidden="true" className="sbui-select__chevron" />
      </button>
      {open && (
        <div
          aria-labelledby={triggerId}
          className={`sbui-select__popup sbui-select__popup--${placement}`}
          id={listboxId}
          role="listbox"
        >
          {items.map((item, index) => (
            <div
              key={item.value}
              aria-disabled={item.disabled || undefined}
              aria-selected={item.value === value}
              className={`sbui-select__option${index === activeIndex ? " sbui-select__option--active" : ""}`}
              id={`${listboxId}-option-${index}`}
              onClick={() => handleOptionClick(item)}
              onMouseEnter={() => {
                if (!item.disabled) setActiveIndex(index);
              }}
              ref={(element) => {
                if (element && index === activeIndex) {
                  element.scrollIntoView({ block: "nearest" });
                }
              }}
              role="option"
            >
              <span>{item.label}</span>
              {item.value === value && (
                <span aria-hidden="true" className="sbui-select__check">
                  ✓
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export interface TabItem {
  value: string;
  label: string;
  content?: ReactNode;
  disabled?: boolean;
}

export interface NavTabItem {
  value: string;
  label: ReactNode;
  disabled?: boolean;
}

export interface NavTabsProps {
  id: string;
  label: string;
  items: readonly NavTabItem[];
  value: string;
  onValueChange: (value: string) => void;
  className?: string;
}

export function NavTabs({
  id,
  label,
  items,
  value,
  onValueChange,
  className = "",
}: NavTabsProps) {
  const selectedIndex = items.findIndex((item) => item.value === value);
  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const direction =
      event.key === "ArrowRight" || event.key === "ArrowDown"
        ? 1
        : event.key === "ArrowLeft" || event.key === "ArrowUp"
          ? -1
          : 0;

    if (!direction || !items.length) return;
    event.preventDefault();

    for (let offset = 1; offset <= items.length; offset += 1) {
      const startIndex =
        selectedIndex >= 0 ? selectedIndex : direction > 0 ? -1 : 0;
      const nextIndex =
        (startIndex + direction * offset + items.length) % items.length;
      const nextItem = items[nextIndex];
      if (!nextItem.disabled) {
        onValueChange(nextItem.value);
        document.getElementById(`${id}-tab-${nextItem.value}`)?.focus();
        return;
      }
    }
  };

  return (
    <div
      aria-label={label}
      className={`sbui-tabs${className ? ` ${className}` : ""}`}
      role="tablist"
    >
      {items.map((item) => {
        const selected = item.value === value;
        return (
          <button
            key={item.value}
            aria-controls={`${id}-panel`}
            aria-selected={selected}
            className="sbui-tab"
            disabled={item.disabled}
            id={`${id}-tab-${item.value}`}
            onClick={() => onValueChange(item.value)}
            onKeyDown={handleKeyDown}
            role="tab"
            tabIndex={selected ? 0 : -1}
            type="button"
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}

export interface TabPanelProps extends HTMLAttributes<HTMLDivElement> {
  labelledBy: string;
}

export function TabPanel({
  labelledBy,
  className = "",
  ...props
}: TabPanelProps) {
  return (
    <div
      {...props}
      aria-labelledby={labelledBy}
      className={`sbui-tab-panel${className ? ` ${className}` : ""}`}
      role="tabpanel"
      tabIndex={0}
    />
  );
}

export interface TabsProps {
  label: string;
  items: readonly TabItem[];
  value: string;
  onValueChange: (value: string) => void;
  className?: string;
}

export function Tabs({
  label,
  items,
  value,
  onValueChange,
  className = "",
}: TabsProps) {
  const id = useId();
  const selectedIndex = items.findIndex((item) => item.value === value);

  return (
    <div className={`sbui-tabs-root${className ? ` ${className}` : ""}`}>
      <NavTabs
        id={id}
        items={items}
        label={label}
        onValueChange={onValueChange}
        value={value}
      />
      {selectedIndex >= 0 && (
        <TabPanel
          id={`${id}-panel`}
          labelledBy={`${id}-tab-${items[selectedIndex].value}`}
        >
          {items[selectedIndex].content}
        </TabPanel>
      )}
    </div>
  );
}

export interface AlertProps extends HTMLAttributes<HTMLDivElement> {
  variant?: "info" | "success" | "warning" | "danger";
  title?: string;
  role?: "alert" | "status";
}

export function Alert({
  variant = "info",
  title,
  role = variant === "danger" ? "alert" : "status",
  className = "",
  children,
  ...props
}: AlertProps) {
  return (
    <div
      {...props}
      className={`sbui-alert sbui-alert--${variant}${className ? ` ${className}` : ""}`}
      role={role}
    >
      {title && <p className="sbui-alert__title">{title}</p>}
      {children && <div className="sbui-alert__body">{children}</div>}
    </div>
  );
}

export interface ThemeProviderProps extends HTMLAttributes<HTMLDivElement> {
  theme: WorkbenchTheme;
}

export function ThemeProvider({
  theme,
  className = "",
  style,
  ...props
}: ThemeProviderProps) {
  const themeStyle = {
    colorScheme: theme.mode,
    "--sb-ui-ink": theme.colors.ink,
    "--sb-ui-panel": theme.colors.panel,
    "--sb-ui-panel-raised": theme.colors.panelRaised,
    "--sb-ui-border": theme.colors.border,
    "--sb-ui-text": theme.colors.text,
    "--sb-ui-text-soft": theme.colors.textSoft,
    "--sb-ui-muted": theme.colors.muted,
    "--sb-ui-accent": theme.colors.accent,
    "--sb-ui-accent-hover": theme.colors.accent,
    "--sb-ui-accent-ink": theme.mode === "dark" ? "#071715" : "#ffffff",
    "--sb-ui-radius-sm": `${theme.radii.sm}px`,
    "--sb-ui-radius-md": `${theme.radii.md}px`,
    "--sb-ui-radius-lg": `${theme.radii.lg}px`,
    "--sb-ui-focus":
      "0 0 0 3px color-mix(in srgb, var(--sb-ui-accent) 32%, transparent)",
    ...style,
  } as CSSProperties;

  return (
    <div
      {...props}
      className={`sbui-theme${theme.mode === "light" ? " sbui-theme-light" : ""}${className ? ` ${className}` : ""}`}
      data-sb-theme={theme.mode}
      style={themeStyle}
    />
  );
}
