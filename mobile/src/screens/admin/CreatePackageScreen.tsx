import React, { useState } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity,
  TextInput, StatusBar, Alert, ActivityIndicator,
  KeyboardAvoidingView, Platform, Modal, Image,
} from 'react-native';
import DateTimePicker, { DateTimePickerEvent } from '@react-native-community/datetimepicker';
import * as ImagePicker from 'expo-image-picker';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { adminAPI } from '../../services/api';

// ─── helpers ──────────────────────────────────────────────────────────────────

const tomorrow = (() => { const d = new Date(); d.setDate(d.getDate()+1); d.setHours(0,0,0,0); return d; })();

const formatDisplay = (d: Date) =>
  `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}`;

const toISO = (d: Date) => d.toISOString().split('T')[0];

const BADGES = ['', 'Hot Deal', 'New', 'Popular', 'Limited', 'Exclusive', 'Staff Pick'];
const CLASSES = ['Economy', 'Business', 'First'];

// ─── types ────────────────────────────────────────────────────────────────────

interface ItineraryDay { day: number; title: string; description: string; }

interface FlightLeg { airline: string; flightNumber: string; from: string; to: string; departure: string; arrival: string; duration: string; stops: number; }

interface FlightInfo { outbound: FlightLeg; return: FlightLeg; class: string; }

interface HotelInfo { name: string; stars: number; location: string; description: string; amenities: string[]; checkIn: string; checkOut: string; }

const emptyLeg = (): FlightLeg => ({ airline:'', flightNumber:'', from:'', to:'', departure:'', arrival:'', duration:'', stops:0 });

// ─── reusable subcomponents ───────────────────────────────────────────────────

const SectionHeader = ({ title, icon }: { title: string; icon: any }) => (
  <View style={s.sectionHeader}>
    <Ionicons name={icon} size={16} color={COLORS.secondary} />
    <Text style={s.sectionTitle}>{title}</Text>
  </View>
);

const Field = ({ label, value, onChangeText, placeholder, multiline, keyboardType, style }: any) => (
  <View style={s.fieldWrap}>
    <Text style={s.fieldLabel}>{label}</Text>
    <TextInput
      style={[s.fieldInput, multiline && s.fieldMultiline, style]}
      value={value} onChangeText={onChangeText}
      placeholder={placeholder} placeholderTextColor={COLORS.textMuted}
      multiline={multiline} keyboardType={keyboardType || 'default'}
      autoCapitalize="sentences"
    />
  </View>
);

const TagList = ({ tags, onRemove }: { tags: string[]; onRemove: (i:number)=>void }) => (
  <View style={s.tagRow}>
    {tags.map((t,i) => (
      <TouchableOpacity key={i} style={s.tag} onPress={() => onRemove(i)}>
        <Text style={s.tagText}>{t}</Text>
        <Ionicons name="close" size={12} color={COLORS.secondary} />
      </TouchableOpacity>
    ))}
  </View>
);

const TagInput = ({ placeholder, onAdd }: { placeholder: string; onAdd: (v:string)=>void }) => {
  const [v, setV] = useState('');
  return (
    <View style={s.tagInputRow}>
      <TextInput
        style={s.tagInput} value={v} onChangeText={setV}
        placeholder={placeholder} placeholderTextColor={COLORS.textMuted}
        returnKeyType="done" onSubmitEditing={() => { if(v.trim()){ onAdd(v.trim()); setV(''); } }}
      />
      <TouchableOpacity style={s.tagAddBtn} onPress={() => { if(v.trim()){ onAdd(v.trim()); setV(''); } }}>
        <Ionicons name="add" size={18} color={COLORS.white} />
      </TouchableOpacity>
    </View>
  );
};

const StarPicker = ({ value, onChange }: { value: number; onChange: (v:number)=>void }) => (
  <View style={{ flexDirection:'row', gap:8 }}>
    {[1,2,3,4,5].map(n => (
      <TouchableOpacity key={n} onPress={() => onChange(n)}>
        <Ionicons name={n <= value ? 'star' : 'star-outline'} size={28} color={COLORS.accent} />
      </TouchableOpacity>
    ))}
  </View>
);

// ─── DatePickerField ──────────────────────────────────────────────────────────

const DatePickerField = ({ label, value, onChange, minDate }: {
  label: string; value: Date | null; onChange: (d: Date) => void; minDate?: Date;
}) => {
  const [show, setShow] = useState(false);
  const [temp, setTemp] = useState(value ?? minDate ?? tomorrow);

  const handleChange = (e: DateTimePickerEvent, d?: Date) => {
    if (Platform.OS === 'android') { setShow(false); if (e.type === 'set' && d) onChange(d); }
    else if (d) setTemp(d);
  };

  return (
    <View style={s.fieldWrap}>
      <Text style={s.fieldLabel}>{label}</Text>
      <TouchableOpacity style={s.dateBtn} onPress={() => { setTemp(value ?? minDate ?? tomorrow); setShow(true); }}>
        <Ionicons name="calendar-outline" size={18} color={COLORS.secondary} />
        <Text style={[s.dateBtnText, !value && {color: COLORS.textMuted}]}>
          {value ? formatDisplay(value) : 'Select date'}
        </Text>
      </TouchableOpacity>
      {Platform.OS === 'android' && show && (
        <DateTimePicker value={temp} mode="date" display="default" minimumDate={minDate} onChange={handleChange} />
      )}
      {Platform.OS === 'ios' && (
        <Modal visible={show} transparent animationType="slide">
          <View style={s.modalOverlay}>
            <View style={s.modalCard}>
              <View style={s.modalHeader}>
                <TouchableOpacity onPress={() => setShow(false)}><Text style={s.modalCancel}>Cancel</Text></TouchableOpacity>
                <Text style={s.modalTitle}>{label}</Text>
                <TouchableOpacity onPress={() => { onChange(temp); setShow(false); }}><Text style={s.modalDone}>Done</Text></TouchableOpacity>
              </View>
              <DateTimePicker value={temp} mode="date" display="inline" minimumDate={minDate} onChange={handleChange} themeVariant="dark" accentColor={COLORS.secondary} style={{ alignSelf:'center' }} />
            </View>
          </View>
        </Modal>
      )}
    </View>
  );
};

// ─── main screen ─────────────────────────────────────────────────────────────

export const CreatePackageScreen: React.FC = () => {
  const navigation = useNavigation();

  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);

  // Step 1 — Cover & Basics
  const [imageUri, setImageUri]       = useState<string|null>(null);
  const [imageBase64, setImageBase64] = useState<string|null>(null);
  const [imageMime, setImageMime]     = useState('image/jpeg');
  const [destination, setDestination] = useState('');
  const [country, setCountry]         = useState('');
  const [depCity, setDepCity]         = useState('');
  const [startDate, setStartDate]     = useState<Date|null>(null);
  const [endDate, setEndDate]         = useState<Date|null>(null);
  const [price, setPrice]             = useState('');
  const [badge, setBadge]             = useState('');
  const [rating, setRating]           = useState('4.8');
  const [showBadgePicker, setShowBadgePicker] = useState(false);

  // Step 2 — Description
  const [summary, setSummary]         = useState('');
  const [highlights, setHighlights]   = useState<string[]>([]);
  const [included, setIncluded]       = useState<string[]>([]);

  // Step 3 — Itinerary
  const [days, setDays] = useState<ItineraryDay[]>([]);

  // Step 4 — Flight & Hotel
  const [hasFlight, setHasFlight] = useState(false);
  const [hasHotel, setHasHotel]   = useState(false);
  const [flightClass, setFlightClass] = useState('Economy');
  const [outbound, setOutbound]   = useState<FlightLeg>(emptyLeg());
  const [returnLeg, setReturnLeg] = useState<FlightLeg>(emptyLeg());
  const [hotel, setHotel]         = useState<HotelInfo>({
    name:'', stars:4, location:'', description:'', amenities:[], checkIn:'14:00', checkOut:'11:00',
  });

  // ─── Image Picker ───────────────────────────────────────────────────────────

  const pickImage = async () => {
    const { status } = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (status !== 'granted') { Alert.alert('Permission needed', 'Please allow photo library access in Settings.'); return; }
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      quality: 0.65, base64: true, allowsEditing: true, aspect: [16, 9],
    });
    if (!result.canceled && result.assets[0]) {
      const asset = result.assets[0];
      setImageUri(asset.uri);
      setImageBase64(asset.base64 || null);
      setImageMime(asset.mimeType || 'image/jpeg');
    }
  };

  // ─── Validation per step ────────────────────────────────────────────────────

  const validateStep = (n: number): boolean => {
    if (n === 1) {
      if (!imageUri)        { Alert.alert('Missing Image', 'Please add a cover photo.'); return false; }
      if (!destination.trim()) { Alert.alert('Missing field', 'Destination is required.'); return false; }
      if (!country.trim())     { Alert.alert('Missing field', 'Country is required.'); return false; }
      if (!startDate)          { Alert.alert('Missing date', 'Please select a start date.'); return false; }
      if (!endDate)            { Alert.alert('Missing date', 'Please select an end date.'); return false; }
      if (endDate <= startDate){ Alert.alert('Invalid dates', 'End date must be after start date.'); return false; }
      if (!price.trim() || isNaN(parseFloat(price)) || parseFloat(price) <= 0)
        { Alert.alert('Invalid price', 'Please enter a valid price.'); return false; }
    }
    if (n === 2) {
      if (!summary.trim()) { Alert.alert('Missing summary', 'Please add a description.'); return false; }
    }
    return true;
  };

  // ─── Submit ─────────────────────────────────────────────────────────────────

  const handleSubmit = async () => {
    if (!validateStep(4)) return;
    setSubmitting(true);
    try {
      let imageUrl = '';
      if (imageBase64) {
        const upRes = await adminAPI.uploadImage(imageBase64, imageMime);
        imageUrl = upRes.data.url;
      }

      const dur = startDate && endDate
        ? Math.max(1, Math.ceil((endDate.getTime() - startDate.getTime()) / 86400000))
        : 7;

      const itinerary = days.map((d, i) => ({
        day: i+1, date:'', title: d.title, description: d.description, activities:[], meals:[],
      }));

      const flightData = hasFlight ? { outbound, return: returnLeg, class: flightClass } : null;
      const hotelData  = hasHotel  ? hotel : null;

      await adminAPI.createDeal({
        title:              destination.trim(),
        name:               destination.trim(),
        location:           `${destination.trim()}, ${country.trim()}`,
        image_url:          imageUrl,
        price:              parseFloat(price),
        rating:             parseFloat(rating) || 4.8,
        badge:              badge || undefined,
        start_date:         startDate ? toISO(startDate) : '',
        end_date:           endDate   ? toISO(endDate)   : '',
        country:            country.trim(),
        summary:            summary.trim(),
        description:        summary.trim(),
        departure_location: depCity.trim(),
        duration:           dur,
        itinerary_json:     JSON.stringify(itinerary),
        flight_json:        JSON.stringify(flightData),
        hotel_json:         JSON.stringify(hotelData),
        highlights_json:    JSON.stringify(highlights),
        included_json:      JSON.stringify(included),
        review_count:       0,
      });

      Alert.alert('✅ Package Created!', `${destination} has been added to the home screen.`,
        [{ text: 'Done', onPress: () => navigation.goBack() }]);
    } catch (err: any) {
      Alert.alert('Error', err?.response?.data?.error || 'Failed to create package. Check image upload config.');
    } finally {
      setSubmitting(false);
    }
  };

  // ─── Step Content ────────────────────────────────────────────────────────────

  const renderStep1 = () => (
    <>
      <SectionHeader title="Cover Photo" icon="image-outline" />
      <TouchableOpacity style={[s.imagePicker, imageUri && s.imagePickerFilled]} onPress={pickImage} activeOpacity={0.8}>
        {imageUri ? (
          <Image source={{ uri: imageUri }} style={s.imagePreview} resizeMode="cover" />
        ) : (
          <View style={s.imagePlaceholder}>
            <Ionicons name="camera-outline" size={36} color={COLORS.textMuted} />
            <Text style={s.imagePlaceholderText}>Tap to upload cover photo</Text>
            <Text style={s.imagePlaceholderSub}>Recommended: 16:9 landscape</Text>
          </View>
        )}
        {imageUri && (
          <View style={s.imageEditBadge}>
            <Ionicons name="pencil" size={14} color={COLORS.white} />
            <Text style={s.imageEditText}>Change</Text>
          </View>
        )}
      </TouchableOpacity>

      <SectionHeader title="Basics" icon="information-circle-outline" />
      <Field label="Destination *" value={destination} onChangeText={setDestination} placeholder="e.g. Santorini" />
      <Field label="Country *" value={country} onChangeText={setCountry} placeholder="e.g. Greece" />
      <Field label="Departure City" value={depCity} onChangeText={setDepCity} placeholder="e.g. Athens (optional)" />
      <DatePickerField label="Start Date *" value={startDate} onChange={setStartDate} minDate={tomorrow} />
      <DatePickerField label="End Date *" value={endDate} onChange={setEndDate} minDate={startDate ?? tomorrow} />
      <Field label="Price (€) *" value={price} onChangeText={setPrice} placeholder="e.g. 1250" keyboardType="number-pad" />
      <Field label="Rating" value={rating} onChangeText={setRating} placeholder="e.g. 4.8" keyboardType="decimal-pad" />

      <View style={s.fieldWrap}>
        <Text style={s.fieldLabel}>Badge (optional)</Text>
        <TouchableOpacity style={s.dateBtn} onPress={() => setShowBadgePicker(true)}>
          <Ionicons name="pricetag-outline" size={18} color={COLORS.secondary} />
          <Text style={[s.dateBtnText, !badge && { color: COLORS.textMuted }]}>{badge || 'None'}</Text>
        </TouchableOpacity>
        <Modal visible={showBadgePicker} transparent animationType="fade">
          <TouchableOpacity style={s.badgeOverlay} activeOpacity={1} onPress={() => setShowBadgePicker(false)}>
            <View style={s.badgeCard}>
              {BADGES.map(b => (
                <TouchableOpacity key={b} style={[s.badgeOption, badge === b && s.badgeOptionSelected]}
                  onPress={() => { setBadge(b); setShowBadgePicker(false); }}>
                  <Text style={[s.badgeOptionText, badge === b && { color: COLORS.secondary }]}>{b || '— None —'}</Text>
                </TouchableOpacity>
              ))}
            </View>
          </TouchableOpacity>
        </Modal>
      </View>
    </>
  );

  const renderStep2 = () => (
    <>
      <SectionHeader title="Description" icon="document-text-outline" />
      <Field label="Summary *" value={summary} onChangeText={setSummary}
        placeholder="Describe this trip experience in a few sentences..."
        multiline style={{ minHeight: 100 }} />

      <SectionHeader title="Highlights" icon="star-outline" />
      <TagList tags={highlights} onRemove={i => setHighlights(highlights.filter((_,idx) => idx !== i))} />
      <TagInput placeholder="Add a highlight (e.g. Private villa)" onAdd={v => setHighlights([...highlights, v])} />

      <SectionHeader title="What's Included" icon="checkmark-circle-outline" />
      <TagList tags={included} onRemove={i => setIncluded(included.filter((_,idx) => idx !== i))} />
      <TagInput placeholder="Add item (e.g. Flights, Hotel, Transfers)" onAdd={v => setIncluded([...included, v])} />
    </>
  );

  const renderStep3 = () => (
    <>
      <SectionHeader title="Day-by-Day Itinerary" icon="calendar-outline" />
      <Text style={s.stepHint}>Add each day of the trip with a title and description. Include activities, restaurants, and experiences.</Text>
      {days.map((d, i) => (
        <View key={i} style={s.dayCard}>
          <View style={s.dayCardHeader}>
            <View style={s.dayBadge}><Text style={s.dayBadgeText}>Day {i+1}</Text></View>
            <TouchableOpacity onPress={() => setDays(days.filter((_,idx) => idx !== i))}>
              <Ionicons name="trash-outline" size={18} color={COLORS.error} />
            </TouchableOpacity>
          </View>
          <TextInput
            style={s.dayTitle} value={d.title} placeholder="Day title (e.g. Arrival & Oia Sunset)"
            placeholderTextColor={COLORS.textMuted}
            onChangeText={v => setDays(days.map((x,idx) => idx===i ? {...x, title:v} : x))}
          />
          <TextInput
            style={s.dayDesc} value={d.description} multiline
            placeholder="What happens this day? Activities, meals, experiences..."
            placeholderTextColor={COLORS.textMuted}
            onChangeText={v => setDays(days.map((x,idx) => idx===i ? {...x, description:v} : x))}
          />
        </View>
      ))}
      <TouchableOpacity style={s.addDayBtn} onPress={() => setDays([...days, { day: days.length+1, title:'', description:'' }])}>
        <Ionicons name="add-circle-outline" size={20} color={COLORS.secondary} />
        <Text style={s.addDayText}>Add Day {days.length+1}</Text>
      </TouchableOpacity>
    </>
  );

  const legField = (leg: FlightLeg, setLeg: (l:FlightLeg)=>void, label: string) => (
    <View style={s.legSection}>
      <Text style={s.legLabel}>{label}</Text>
      {([['Airline','airline'],['Flight #','flightNumber'],['From','from'],['To','to'],
         ['Departure','departure'],['Arrival','arrival'],['Duration','duration']] as [string,keyof FlightLeg][]).map(([lbl,key]) => (
        <TextInput key={key} style={s.legInput}
          placeholder={lbl} placeholderTextColor={COLORS.textMuted}
          value={String(leg[key])}
          onChangeText={v => setLeg({...leg, [key]: v})}
        />
      ))}
      <View style={{ flexDirection:'row', gap: SPACING.sm, marginTop: SPACING.xs }}>
        {[0,1,2].map(n => (
          <TouchableOpacity key={n} style={[s.stopBtn, leg.stops===n && s.stopBtnActive]}
            onPress={() => setLeg({...leg, stops:n})}>
            <Text style={[s.stopText, leg.stops===n && s.stopTextActive]}>{n===0?'Direct':n===1?'1 Stop':'2+ Stops'}</Text>
          </TouchableOpacity>
        ))}
      </View>
    </View>
  );

  const renderStep4 = () => (
    <>
      {/* Flight */}
      <SectionHeader title="Flight Details (optional)" icon="airplane-outline" />
      <TouchableOpacity style={s.toggleRow} onPress={() => setHasFlight(!hasFlight)}>
        <View style={[s.toggle, hasFlight && s.toggleOn]}>
          <View style={[s.toggleThumb, hasFlight && s.toggleThumbOn]} />
        </View>
        <Text style={s.toggleLabel}>{hasFlight ? 'Flight info included' : 'No flight info'}</Text>
      </TouchableOpacity>

      {hasFlight && (
        <>
          {legField(outbound, setOutbound, 'Outbound Flight')}
          {legField(returnLeg, setReturnLeg, 'Return Flight')}
          <View style={s.fieldWrap}>
            <Text style={s.fieldLabel}>Cabin Class</Text>
            <View style={{ flexDirection:'row', gap: SPACING.sm }}>
              {CLASSES.map(c => (
                <TouchableOpacity key={c} style={[s.classBtn, flightClass===c && s.classBtnActive]}
                  onPress={() => setFlightClass(c)}>
                  <Text style={[s.classText, flightClass===c && s.classTextActive]}>{c}</Text>
                </TouchableOpacity>
              ))}
            </View>
          </View>
        </>
      )}

      {/* Hotel */}
      <SectionHeader title="Hotel Details (optional)" icon="bed-outline" />
      <TouchableOpacity style={s.toggleRow} onPress={() => setHasHotel(!hasHotel)}>
        <View style={[s.toggle, hasHotel && s.toggleOn]}>
          <View style={[s.toggleThumb, hasHotel && s.toggleThumbOn]} />
        </View>
        <Text style={s.toggleLabel}>{hasHotel ? 'Hotel info included' : 'No hotel info'}</Text>
      </TouchableOpacity>

      {hasHotel && (
        <>
          <Field label="Hotel Name" value={hotel.name} onChangeText={v => setHotel({...hotel,name:v})} placeholder="e.g. Canaves Oia Epitome" />
          <View style={s.fieldWrap}>
            <Text style={s.fieldLabel}>Stars</Text>
            <StarPicker value={hotel.stars} onChange={v => setHotel({...hotel,stars:v})} />
          </View>
          <Field label="Location" value={hotel.location} onChangeText={v => setHotel({...hotel,location:v})} placeholder="e.g. Oia, Santorini" />
          <Field label="Description" value={hotel.description} onChangeText={v => setHotel({...hotel,description:v})} placeholder="Brief hotel description..." multiline />
          <Field label="Check-in Time" value={hotel.checkIn} onChangeText={v => setHotel({...hotel,checkIn:v})} placeholder="e.g. 14:00" />
          <Field label="Check-out Time" value={hotel.checkOut} onChangeText={v => setHotel({...hotel,checkOut:v})} placeholder="e.g. 11:00" />
          <View style={s.fieldWrap}>
            <Text style={s.fieldLabel}>Amenities</Text>
            <TagList tags={hotel.amenities} onRemove={i => setHotel({...hotel, amenities: hotel.amenities.filter((_,idx)=>idx!==i)})} />
            <TagInput placeholder="Add amenity (e.g. Pool, Spa, Sea View)" onAdd={v => setHotel({...hotel, amenities:[...hotel.amenities, v]})} />
          </View>
        </>
      )}
    </>
  );

  // ─── render ───────────────────────────────────────────────────────────────────

  const STEPS = ['Cover & Basics', 'Description', 'Itinerary', 'Flight & Hotel'];

  return (
    <View style={s.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={s.header}>
        <TouchableOpacity style={s.backBtn} onPress={() => step === 1 ? navigation.goBack() : setStep(step-1)}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={s.headerTitle}>New Package</Text>
        <View style={{ width: 38 }} />
      </View>

      {/* Progress */}
      <View style={s.progress}>
        {STEPS.map((lbl, i) => (
          <View key={i} style={s.progressStep}>
            <View style={[s.progressDot, step > i && s.progressDotDone, step === i+1 && s.progressDotActive]}>
              {step > i
                ? <Ionicons name="checkmark" size={12} color={COLORS.white} />
                : <Text style={[s.progressNum, step === i+1 && s.progressNumActive]}>{i+1}</Text>
              }
            </View>
            {i < STEPS.length-1 && <View style={[s.progressLine, step > i+1 && s.progressLineDone]} />}
          </View>
        ))}
      </View>
      <Text style={s.stepName}>{STEPS[step-1]}</Text>

      <KeyboardAvoidingView style={{ flex:1 }} behavior={Platform.OS==='ios'?'padding':'height'} keyboardVerticalOffset={100}>
        <ScrollView style={s.scroll} showsVerticalScrollIndicator={false} keyboardShouldPersistTaps="handled" contentContainerStyle={s.content}>
          {step === 1 && renderStep1()}
          {step === 2 && renderStep2()}
          {step === 3 && renderStep3()}
          {step === 4 && renderStep4()}
          <View style={{ height: 100 }} />
        </ScrollView>
      </KeyboardAvoidingView>

      {/* Footer */}
      <View style={s.footer}>
        {step < 4 ? (
          <TouchableOpacity style={s.nextBtn} onPress={() => { if (validateStep(step)) setStep(step+1); }}>
            <Text style={s.nextBtnText}>Next — {STEPS[step]}</Text>
            <Ionicons name="arrow-forward" size={18} color={COLORS.white} />
          </TouchableOpacity>
        ) : (
          <TouchableOpacity style={[s.nextBtn, submitting && { opacity: 0.6 }]}
            onPress={handleSubmit} disabled={submitting}>
            {submitting
              ? <><ActivityIndicator color={COLORS.white} size="small" /><Text style={s.nextBtnText}>Creating...</Text></>
              : <><Ionicons name="checkmark-circle" size={18} color={COLORS.white} /><Text style={s.nextBtnText}>Create Package</Text></>
            }
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
};

// ─── styles ───────────────────────────────────────────────────────────────────

const s = StyleSheet.create({
  container: { flex:1, backgroundColor: COLORS.background },
  header: {
    flexDirection:'row', alignItems:'center', justifyContent:'space-between',
    paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md,
  },
  backBtn: { width:38, height:38, borderRadius:RADIUS.full, backgroundColor:COLORS.surface, alignItems:'center', justifyContent:'center' },
  headerTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight:'700' },

  progress: { flexDirection:'row', alignItems:'center', paddingHorizontal: SPACING.lg, marginBottom: 4 },
  progressStep: { flexDirection:'row', alignItems:'center', flex:1 },
  progressDot: { width:24, height:24, borderRadius:12, backgroundColor: COLORS.surface, borderWidth:1.5, borderColor: COLORS.border, alignItems:'center', justifyContent:'center' },
  progressDotActive: { borderColor: COLORS.secondary, backgroundColor:'rgba(108,60,225,0.15)' },
  progressDotDone: { backgroundColor: COLORS.secondary, borderColor: COLORS.secondary },
  progressNum: { color: COLORS.textMuted, fontSize: 11, fontWeight:'700' },
  progressNumActive: { color: COLORS.secondary },
  progressLine: { flex:1, height:2, backgroundColor: COLORS.border, marginHorizontal: 2 },
  progressLineDone: { backgroundColor: COLORS.secondary },

  stepName: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, fontWeight:'600', paddingHorizontal: SPACING.lg, marginBottom: SPACING.md, letterSpacing:0.3 },

  scroll: { flex:1 },
  content: { paddingHorizontal: SPACING.lg, paddingBottom: SPACING.lg },

  sectionHeader: { flexDirection:'row', alignItems:'center', gap: SPACING.sm, marginTop: SPACING.lg, marginBottom: SPACING.sm },
  sectionTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight:'700' },

  fieldWrap: { marginBottom: SPACING.md },
  fieldLabel: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, fontWeight:'600', letterSpacing:0.3, marginBottom: 6 },
  fieldInput: { backgroundColor: COLORS.surface, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border, paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm+2, color: COLORS.text, fontSize: FONTS.sizes.md },
  fieldMultiline: { minHeight:80, textAlignVertical:'top', paddingTop: SPACING.sm },

  dateBtn: { flexDirection:'row', alignItems:'center', gap: SPACING.sm, backgroundColor: COLORS.surface, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border, paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm+4 },
  dateBtnText: { color: COLORS.text, fontSize: FONTS.sizes.md, flex:1 },

  modalOverlay: { flex:1, backgroundColor:'rgba(0,0,0,0.6)', justifyContent:'flex-end' },
  modalCard: { backgroundColor: COLORS.surface, borderTopLeftRadius: RADIUS.xl, borderTopRightRadius: RADIUS.xl, paddingBottom: SPACING.xxl },
  modalHeader: { flexDirection:'row', justifyContent:'space-between', alignItems:'center', paddingHorizontal: SPACING.lg, paddingVertical: SPACING.md, borderBottomWidth:1, borderBottomColor: COLORS.border },
  modalTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight:'700' },
  modalCancel: { color: COLORS.textMuted, fontSize: FONTS.sizes.md },
  modalDone: { color: COLORS.secondary, fontSize: FONTS.sizes.md, fontWeight:'700' },

  imagePicker: { height:180, borderRadius: RADIUS.xl, borderWidth:1.5, borderColor: COLORS.border, borderStyle:'dashed', overflow:'hidden', marginBottom: SPACING.md },
  imagePickerFilled: { borderStyle:'solid', borderColor: COLORS.secondary },
  imagePreview: { width:'100%', height:'100%' },
  imagePlaceholder: { flex:1, alignItems:'center', justifyContent:'center', gap: SPACING.sm },
  imagePlaceholderText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md, fontWeight:'600' },
  imagePlaceholderSub: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
  imageEditBadge: { position:'absolute', bottom:8, right:8, flexDirection:'row', alignItems:'center', gap:4, backgroundColor:'rgba(0,0,0,0.6)', borderRadius: RADIUS.full, paddingHorizontal:10, paddingVertical:4 },
  imageEditText: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight:'600' },

  badgeOverlay: { flex:1, backgroundColor:'rgba(0,0,0,0.5)', justifyContent:'center', alignItems:'center' },
  badgeCard: { backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, width:240, overflow:'hidden', borderWidth:1, borderColor: COLORS.border },
  badgeOption: { paddingHorizontal: SPACING.lg, paddingVertical: SPACING.md, borderBottomWidth:1, borderBottomColor: COLORS.border },
  badgeOptionSelected: { backgroundColor:'rgba(108,60,225,0.1)' },
  badgeOptionText: { color: COLORS.text, fontSize: FONTS.sizes.md },

  tagRow: { flexDirection:'row', flexWrap:'wrap', gap: SPACING.xs, marginBottom: SPACING.sm },
  tag: { flexDirection:'row', alignItems:'center', gap:4, backgroundColor:'rgba(108,60,225,0.15)', borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm, paddingVertical:4, borderWidth:1, borderColor:'rgba(108,60,225,0.3)' },
  tagText: { color: COLORS.secondary, fontSize: FONTS.sizes.xs, fontWeight:'600' },
  tagInputRow: { flexDirection:'row', alignItems:'center', gap: SPACING.sm },
  tagInput: { flex:1, backgroundColor: COLORS.surface, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border, paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm, color: COLORS.text, fontSize: FONTS.sizes.sm },
  tagAddBtn: { width:36, height:36, borderRadius: RADIUS.full, backgroundColor: COLORS.secondary, alignItems:'center', justifyContent:'center' },

  stepHint: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, lineHeight:20, marginBottom: SPACING.md },

  dayCard: { backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, padding: SPACING.md, marginBottom: SPACING.md, borderWidth:1, borderColor: COLORS.border },
  dayCardHeader: { flexDirection:'row', alignItems:'center', justifyContent:'space-between', marginBottom: SPACING.sm },
  dayBadge: { backgroundColor:'rgba(108,60,225,0.15)', borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm, paddingVertical:3 },
  dayBadgeText: { color: COLORS.secondary, fontSize: FONTS.sizes.xs, fontWeight:'700' },
  dayTitle: { backgroundColor: COLORS.background, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border, paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm, color: COLORS.text, fontSize: FONTS.sizes.md, marginBottom: SPACING.sm },
  dayDesc: { backgroundColor: COLORS.background, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border, paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm, color: COLORS.text, fontSize: FONTS.sizes.sm, minHeight:80, textAlignVertical:'top' },
  addDayBtn: { flexDirection:'row', alignItems:'center', gap: SPACING.sm, borderRadius: RADIUS.xl, borderWidth:1.5, borderColor: COLORS.secondary, borderStyle:'dashed', padding: SPACING.md, justifyContent:'center' },
  addDayText: { color: COLORS.secondary, fontSize: FONTS.sizes.md, fontWeight:'600' },

  legSection: { backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, padding: SPACING.md, marginBottom: SPACING.md, borderWidth:1, borderColor: COLORS.border },
  legLabel: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight:'700', marginBottom: SPACING.sm },
  legInput: { backgroundColor: COLORS.background, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border, paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm, color: COLORS.text, fontSize: FONTS.sizes.sm, marginBottom: SPACING.xs },
  stopBtn: { flex:1, alignItems:'center', paddingVertical: SPACING.sm, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border },
  stopBtnActive: { borderColor: COLORS.secondary, backgroundColor:'rgba(108,60,225,0.15)' },
  stopText: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, fontWeight:'600' },
  stopTextActive: { color: COLORS.secondary },

  toggleRow: { flexDirection:'row', alignItems:'center', gap: SPACING.md, marginBottom: SPACING.md },
  toggle: { width:48, height:26, borderRadius:13, backgroundColor: COLORS.border, padding:2 },
  toggleOn: { backgroundColor: COLORS.secondary },
  toggleThumb: { width:22, height:22, borderRadius:11, backgroundColor: COLORS.white },
  toggleThumbOn: { transform:[{translateX:22}] },
  toggleLabel: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, fontWeight:'600' },

  classBtn: { flex:1, alignItems:'center', paddingVertical: SPACING.sm, borderRadius: RADIUS.md, borderWidth:1, borderColor: COLORS.border },
  classBtnActive: { borderColor: COLORS.accent, backgroundColor:'rgba(245,166,35,0.12)' },
  classText: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, fontWeight:'600' },
  classTextActive: { color: COLORS.accent },

  footer: { padding: SPACING.lg, paddingBottom: SPACING.xxl, backgroundColor: COLORS.background },
  nextBtn: { flexDirection:'row', alignItems:'center', justifyContent:'center', gap: SPACING.sm, backgroundColor: COLORS.secondary, borderRadius: RADIUS.xl, paddingVertical: SPACING.md+2 },
  nextBtnText: { color: COLORS.white, fontSize: FONTS.sizes.md, fontWeight:'700' },
});
